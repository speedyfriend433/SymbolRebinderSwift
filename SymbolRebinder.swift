import Foundation
import MachO
import Dispatch
import Darwin

// MARK: - Symbol Rebinding Core

struct SymbolRebinder {
    private static let synchronizationQueue = DispatchQueue(label: "com.symbolrebinder.queue", attributes: .concurrent)
    private static let symbolCache = NSCache<NSString, NSString>()
    
    // MARK: - Public API
    
    static func performSymbolicRebinding(targetSymbol: String,
                                        replacementImplementation: UnsafeRawPointer,
                                        originalImplementationReference: UnsafeMutablePointer<UnsafeRawPointer?>?) -> RebindingResult {
        synchronizationQueue.sync(flags: .barrier) {
            return _performSymbolicRebinding(targetSymbol: targetSymbol,
                                          replacementImplementation: replacementImplementation,
                                          originalImplementationReference: originalImplementationReference)
        }
    }
    
    static func batchRebind(operations: [RebindingOperation]) -> [RebindingResult] {
        return operations.map { operation in
            performSymbolicRebinding(targetSymbol: operation.targetSymbol,
                                   replacementImplementation: operation.replacementImplementation,
                                   originalImplementationReference: operation.originalImplementationReference)
        }
    }
    
    static func enumerateLoadedImages() -> [LoadedImageInfo] {
        var images = [LoadedImageInfo]()
        let count = _dyld_image_count()
        
        for i in 0..<count {
            if let header = _dyld_get_image_header(i) {
                let slide = _dyld_get_image_vmaddr_slide(i)
                let name = String(cString: _dyld_get_image_name(i))
                images.append(LoadedImageInfo(header: header, slide: slide, name: name))
            }
        }
        
        return images
    }
    
    // MARK: - Private Implementation
    
    private static func _performSymbolicRebinding(targetSymbol: String,
                                                 replacementImplementation: UnsafeRawPointer,
                                                 originalImplementationReference: UnsafeMutablePointer<UnsafeRawPointer?>?) -> RebindingResult {
        let startTime = mach_absolute_time()
        var result = RebindingResult(success: false, symbol: targetSymbol, error: nil)
        
        for image in enumerateLoadedImages() {
            if let rebindInfo = rebindSymbolInImage(image: image,
                                                  targetSymbol: targetSymbol,
                                                  replacementImplementation: replacementImplementation,
                                                  originalImplementationReference: originalImplementationReference) {
                result.success = rebindInfo.success
                result.imageName = rebindInfo.imageName
                result.symbolAddress = rebindInfo.symbolAddress
                break
            }
        }
        
        result.duration = machTimeToNanoseconds(mach_absolute_time() - startTime)
        return result
    }
    
    private static func rebindSymbolInImage(image: LoadedImageInfo,
                                           targetSymbol: String,
                                           replacementImplementation: UnsafeRawPointer,
                                           originalImplementationReference: UnsafeMutablePointer<UnsafeRawPointer?>?) -> RebindingInfo? {
        guard let header = image.header else { return nil }
        
        if let lazySymbolPointerSection = getsectbyname("__DATA", "__la_symbol_ptr") ?? getsectbyname("__DATA_CONST", "__la_symbol_ptr") {
            let sectionPtr = unsafeBitCast(lazySymbolPointerSection, to: UnsafePointer<section>.self)
            return processLazySymbols(header: header,
                                    slide: image.slide,
                                    section: sectionPtr,
                                    targetSymbol: targetSymbol,
                                    replacementImplementation: replacementImplementation,
                                    originalImplementationReference: originalImplementationReference,
                                    imageName: image.name)
        }
        
        return nil
    }
    
    private static func processLazySymbols(header: UnsafePointer<mach_header>,
                                         slide: Int,
                                         section: UnsafePointer<section>,
                                         targetSymbol: String,
                                         replacementImplementation: UnsafeRawPointer,
                                         originalImplementationReference: UnsafeMutablePointer<UnsafeRawPointer?>?,
                                         imageName: String) -> RebindingInfo? {
        let symbolTableOffset = Int(section.pointee.reserved1)
        let symbolTableBase = UnsafeRawPointer(header).advanced(by: slide + symbolTableOffset)
        var rebindInfo: RebindingInfo?
        
        for i in 0..<Int(section.pointee.size) / MemoryLayout<UnsafeRawPointer>.size {
            let currentSymbolPointer = symbolTableBase.advanced(by: i * MemoryLayout<UnsafeRawPointer>.size)
            let originalSymbolImplementation = currentSymbolPointer.load(as: UnsafeRawPointer.self)
            
            if let resolvedSymbolName = resolveSymbolNameFromAddress(symbolAddress: originalSymbolImplementation),
               resolvedSymbolName == targetSymbol {
                
                originalImplementationReference?.pointee = originalSymbolImplementation
                let rebindLocation = UnsafeMutableRawPointer(mutating: currentSymbolPointer)
                
                if performAtomicRebind(original: originalSymbolImplementation,
                                     replacement: replacementImplementation,
                                     location: rebindLocation) {
                    rebindInfo = RebindingInfo(success: true,
                                             imageName: imageName,
                                             symbolAddress: originalSymbolImplementation)
                    break
                }
            }
        }
        
        return rebindInfo
    }
    
    private static func performAtomicRebind(original: UnsafeRawPointer,
                                           replacement: UnsafeRawPointer,
                                           location: UnsafeMutableRawPointer) -> Bool {
        #if os(macOS) || os(iOS)
        let rebindLocationMutable = location.assumingMemoryBound(to: UnsafeMutableRawPointer?.self)
        var expected = UnsafeMutableRawPointer(mutating: original)
        let desired = UnsafeMutableRawPointer(mutating: replacement)
        return OSAtomicCompareAndSwapPtrBarrier(expected, desired, rebindLocationMutable)
        #else
        var expected = original
        return location.atomicCompareExchange(expected: expected, desired: replacement)
        #endif
    }
    
    // MARK: - Symbol Resolution
    
    private static var customSymbolCache = [String: String]()
    private static let cacheQueue = DispatchQueue(label: "com.symbolrebinder.cache", attributes: .concurrent)
    private static func resolveSymbolNameFromAddress(symbolAddress: UnsafeRawPointer) -> String? {
        let addressString = "\(symbolAddress)"
        
        if let cachedName = cacheQueue.sync(execute: { customSymbolCache[addressString] }) {
            return cachedName
        }
        
        guard let header = _dyld_get_image_header(0) else { return nil }
        let slide = _dyld_get_image_vmaddr_slide(0)
        
        let mh = unsafeBitCast(header, to: UnsafePointer<mach_header_64>.self)
        var cmdPtr = UnsafeRawPointer(mh.advanced(by: 1))
        
        for _ in 0..<mh.pointee.ncmds {
            let cmd = cmdPtr.load(as: load_command.self)
            
            if cmd.cmd == LC_SYMTAB {
                let symtabCmd = cmdPtr.load(as: symtab_command.self)
                let symtab = cmdPtr.advanced(by: Int(symtabCmd.symoff)).assumingMemoryBound(to: nlist_64.self)
                let strtab = cmdPtr.advanced(by: Int(symtabCmd.stroff)).assumingMemoryBound(to: CChar.self)
                
                for i in 0..<Int(symtabCmd.nsyms) {
                    let sym = symtab.advanced(by: i)
                    let namePtr = strtab.advanced(by: Int(sym.pointee.n_un.n_strx))
                    let symAddr = UnsafeRawPointer(bitPattern: UInt(sym.pointee.n_value) + UInt(slide))
                    
                    if symAddr == symbolAddress {
                        let name = String(cString: namePtr)
                        cacheQueue.async(flags: .barrier) {
                            customSymbolCache[addressString] = name
                        }
                        return name
                    }
                }
            }
            
            cmdPtr = cmdPtr.advanced(by: Int(cmd.cmdsize))
        }
        
        return nil
    }
    
    // MARK: - Utility Functions
    
    private static func machTimeToNanoseconds(_ machTime: UInt64) -> UInt64 {
        var timebase = mach_timebase_info()
        mach_timebase_info(&timebase)
        return machTime * UInt64(timebase.numer) / UInt64(timebase.denom)
    }
}

// MARK: - Data Structures

struct RebindingOperation {
    let targetSymbol: String
    let replacementImplementation: UnsafeRawPointer
    let originalImplementationReference: UnsafeMutablePointer<UnsafeRawPointer?>?
}

struct RebindingResult {
    var success: Bool
    let symbol: String
    var error: String?
    var imageName: String?
    var symbolAddress: UnsafeRawPointer?
    var duration: UInt64 = 0
}

struct RebindingInfo {
    let success: Bool
    let imageName: String
    let symbolAddress: UnsafeRawPointer
}

struct LoadedImageInfo {
    let header: UnsafePointer<mach_header>?
    let slide: Int
    let name: String
}

// MARK: - Advanced Features

extension SymbolRebinder {
    static func findSymbolAddress(_ symbol: String) -> UnsafeRawPointer? {
        for image in enumerateLoadedImages() {
            if let address = findSymbolInImage(image: image, symbol: symbol) {
                return address
            }
        }
        return nil
    }
    
    private static func findSymbolInImage(image: LoadedImageInfo, symbol: String) -> UnsafeRawPointer? {
        guard let header = image.header else { return nil }
        
        let mh = unsafeBitCast(header, to: UnsafePointer<mach_header_64>.self)
        var cmdPtr = UnsafeRawPointer(mh.advanced(by: 1))
        
        for _ in 0..<mh.pointee.ncmds {
            let cmd = cmdPtr.load(as: load_command.self)
            
            if cmd.cmd == LC_SYMTAB {
                let symtabCmd = cmdPtr.load(as: symtab_command.self)
                let symtab = cmdPtr.advanced(by: Int(symtabCmd.symoff)).assumingMemoryBound(to: nlist_64.self)
                let strtab = cmdPtr.advanced(by: Int(symtabCmd.stroff)).assumingMemoryBound(to: CChar.self)
                
                for i in 0..<Int(symtabCmd.nsyms) {
                    let sym = symtab.advanced(by: i)
                    let namePtr = strtab.advanced(by: Int(sym.pointee.n_un.n_strx))
                    let name = String(cString: namePtr)
                    
                    if name == symbol {
                        return UnsafeRawPointer(bitPattern: UInt(sym.pointee.n_value) + UInt(image.slide))
                    }
                }
            }
            
            cmdPtr = cmdPtr.advanced(by: Int(cmd.cmdsize))
        }
        
        return nil
    }
}

// MARK: - Thread Safety Extensions

extension SymbolRebinder {
    static func withExclusiveAccess<T>(_ block: () throws -> T) rethrows -> T {
        return try synchronizationQueue.sync(flags: .barrier, execute: block)
    }
    
    static func clearSymbolCache() {
        synchronizationQueue.sync(flags: .barrier) {
            symbolCache.removeAllObjects()
        }
    }
}

// MARK: - Performance Monitoring

extension SymbolRebinder {
    struct PerformanceMetrics {
        static var totalRebinds: UInt64 = 0
        static var totalTime: UInt64 = 0
        static var fastestRebind: UInt64 = UInt64.max
        static var slowestRebind: UInt64 = 0
        
        static func recordRebind(duration: UInt64) {
            totalRebinds += 1
            totalTime += duration
            fastestRebind = min(fastestRebind, duration)
            slowestRebind = max(slowestRebind, duration)
        }
        
        static func averageTime() -> Double {
            return totalRebinds > 0 ? Double(totalTime) / Double(totalRebinds) : 0
        }
    }
}

// MARK: - Error Handling

enum SymbolRebinderError: Error {
    case symbolNotFound
    case imageNotFound
    case invalidSymbolFormat
    case permissionDenied
    case memoryAccessViolation
    case unsupportedArchitecture
}

// MARK: - Debug Utilities

#if DEBUG
extension SymbolRebinder {
    static func debugPrintImageInfo() {
        let images = enumerateLoadedImages()
        print("=== Loaded Images ===")
        images.forEach { image in
            print("""
            Name: \(image.name)
            Header: \(String(format: "%p", image.header!))
            Slide: 0x\(String(format: "%lx", image.slide))
            """)
        }
    }
    
    #if DEBUG
    static func debugPrintSymbolCache() {
        print("=== Symbol Cache ===")
        print("Symbol cache contents not directly enumerable - use debug tools to inspect NSCache")
    }
    #endif
}
#endif

static func clearSymbolCache() {
    cacheQueue.async(flags: .barrier) {
        customSymbolCache.removeAll()
    }
}

#if DEBUG
static func debugPrintSymbolCache() {
    print("=== Symbol Cache ===")
    cacheQueue.sync {
        for (key, value) in customSymbolCache {
            print("\(key): \(value)")
        }
    }
}
#endif
