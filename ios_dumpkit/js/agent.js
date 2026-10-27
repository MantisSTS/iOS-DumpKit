'use strict';

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;
var O_TRUNC = 1024;
var SEEK_SET = 0;
var RTLD_NOW = 2;
var RTLD_GLOBAL = 8;
var DT_DIR = 4;
var DT_LNK = 10;
var DT_UNKNOWN = 0;

var MH_MAGIC = 0xfeedface;
var MH_MAGIC_64 = 0xfeedfacf;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2c;

var cached = {};

function sendEvent(event, payload) {
  send({ event: event, payload: payload || {} });
}

function allocStr(value) {
  return Memory.allocUtf8String(value);
}

function findExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    try {
      return Module.findGlobalExportByName(name);
    } catch (_) {}
  }
  if (typeof Module.getGlobalExportByName === 'function') {
    try {
      return Module.getGlobalExportByName(name);
    } catch (_) {}
  }
  if (typeof Module.findExportByName === 'function') {
    try {
      return Module.findExportByName(null, name);
    } catch (_) {}
  }
  return null;
}

function native(name, ret, args) {
  if (!cached[name]) {
    var ptrValue = findExport(name);
    if (!ptrValue) {
      throw new Error('Native export not found: ' + name);
    }
    cached[name] = new NativeFunction(ptrValue, ret, args);
  }
  return cached[name];
}

function enumerateModulesCompat() {
  if (typeof Process.enumerateModules === 'function') {
    return Process.enumerateModules();
  }
  if (typeof Process.enumerateModulesSync === 'function') {
    return Process.enumerateModulesSync();
  }
  return [];
}

function getDirentOffsets() {
  if (Process.pointerSize === 8) {
    return { namlen: 18, dtype: 20, name: 21 };
  }
  return { namlen: 10, dtype: 12, name: 13 };
}

function tryLoadObjC() {
  if (typeof ObjC !== 'undefined' && ObjC.available) {
    return true;
  }
  try {
    if (typeof Module.load === 'function') {
      Module.load('/usr/lib/libobjc.A.dylib');
    }
  } catch (_) {}
  try {
    native('dlopen', 'pointer', ['pointer', 'int'])(
      allocStr('/usr/lib/libobjc.A.dylib'),
      RTLD_NOW | RTLD_GLOBAL
    );
  } catch (_) {}
  try {
    if (typeof Module.ensureInitialized === 'function') {
      Module.ensureInitialized('Foundation');
    }
  } catch (_) {}
  return typeof ObjC !== 'undefined' && ObjC.available;
}

function getMainModuleFallback() {
  if (Process.mainModule) {
    return Process.mainModule;
  }
  var modules = enumerateModulesCompat();
  return modules.length ? modules[0] : null;
}

function getBundleInfo() {
  var fallback = getMainModuleFallback();
  var info = {
    bundleId: null,
    appName: fallback ? fallback.name : null,
    bundlePath: null,
    executablePath: fallback ? fallback.path : null,
    executableName: fallback ? fallback.name : null,
    dataContainer: null,
    groupContainers: []
  };

  if (fallback && fallback.path.indexOf('.app/') !== -1) {
    info.bundlePath = fallback.path.substring(0, fallback.path.indexOf('.app/') + 4);
  }

  // Resolve the sandbox Data container (HOME) without requiring the ObjC
  // runtime, which is not always available in-process. This is what --rootless
  // staging relies on, so it must work even when the ObjC branch below is skipped.
  try {
    var getenv = native('getenv', 'pointer', ['pointer']);
    var homePtr = getenv(allocStr('HOME'));
    if (homePtr && !homePtr.isNull()) {
      var home = homePtr.readUtf8String();
      if (home) {
        info.dataContainer = home;
      }
    }
  } catch (_) {}

  if (!tryLoadObjC()) {
    return info;
  }

  var bundle = ObjC.classes.NSBundle.mainBundle();
  var infoDict = bundle.infoDictionary();
  var displayName = infoDict.objectForKey_('CFBundleDisplayName');
  var bundleName = infoDict.objectForKey_('CFBundleName');
  var bundleId = bundle.bundleIdentifier();
  var bundlePath = bundle.bundlePath();
  var executablePath = bundle.executablePath();

  info.bundleId = bundleId ? bundleId.toString() : info.bundleId;
  info.appName = displayName
    ? displayName.toString()
    : bundleName
      ? bundleName.toString()
      : info.appName;
  info.bundlePath = bundlePath ? bundlePath.toString() : info.bundlePath;
  info.executablePath = executablePath ? executablePath.toString() : info.executablePath;
  info.executableName = info.executablePath ? info.executablePath.split('/').pop() : info.executableName;

  try {
    var env = ObjC.classes.NSProcessInfo.processInfo().environment();
    var home = env.objectForKey_('HOME');
    info.dataContainer = home ? home.toString() : null;
  } catch (_) {}

  try {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var urls = fm.containerURLForSecurityApplicationGroupIdentifier_;
    if (urls) {
      info.groupContainers = [];
    }
  } catch (_) {}

  return info;
}

function getGroupContainers(identifiers) {
  var result = {};
  if (!tryLoadObjC()) {
    return result;
  }
  var fm = ObjC.classes.NSFileManager.defaultManager();
  for (var i = 0; i < identifiers.length; i++) {
    var identifier = identifiers[i];
    try {
      var url = fm.containerURLForSecurityApplicationGroupIdentifier_(identifier);
      if (url) {
        result[identifier] = url.path().toString();
      }
    } catch (_) {}
  }
  return result;
}

function readSegmentName(ptrValue) {
  var bytes = new Uint8Array(ptrValue.readByteArray(16));
  var chars = [];
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      break;
    }
    chars.push(String.fromCharCode(bytes[i]));
  }
  return chars.join('');
}

function readU64Number(ptrValue) {
  return ptrValue.readU64().toNumber();
}

function parseMachO(base) {
  var magic = base.readU32();
  var is64 = magic === MH_MAGIC_64;
  if (!is64 && magic !== MH_MAGIC) {
    return { valid: false, encrypted: false, encryption: null, segments: [], machoType: null };
  }

  var headerSize = is64 ? 32 : 28;
  var ncmds = base.add(16).readU32();
  var cursor = headerSize;
  var segments = [];
  var encryption = null;
  var machoType = base.add(12).readU32();

  for (var i = 0; i < ncmds; i++) {
    var cmd = base.add(cursor).readU32();
    var cmdsize = base.add(cursor + 4).readU32();
    if (cmdsize < 8) {
      throw new Error('Invalid Mach-O load command size at index ' + i);
    }

    if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
      var segname = readSegmentName(base.add(cursor + 8));
      var vmaddr = is64 ? readU64Number(base.add(cursor + 24)) : base.add(cursor + 24).readU32();
      var vmsize = is64 ? readU64Number(base.add(cursor + 32)) : base.add(cursor + 28).readU32();
      var fileoff = is64 ? readU64Number(base.add(cursor + 40)) : base.add(cursor + 32).readU32();
      var filesize = is64 ? readU64Number(base.add(cursor + 48)) : base.add(cursor + 36).readU32();
      segments.push({
        segname: segname,
        vmaddr: vmaddr,
        vmsize: vmsize,
        fileoff: fileoff,
        filesize: filesize
      });
    }

    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      encryption = {
        cryptoff: base.add(cursor + 8).readU32(),
        cryptsize: base.add(cursor + 12).readU32(),
        cryptid: base.add(cursor + 16).readU32(),
        cryptidFileOffset: cursor + 16
      };
    }
    cursor += cmdsize;
  }

  return {
    valid: true,
    encrypted: encryption !== null && encryption.cryptid !== 0,
    encryption: encryption,
    segments: segments,
    machoType: machoType
  };
}

function relativeToBundle(bundlePath, path) {
  if (bundlePath && path.indexOf(bundlePath + '/') === 0) {
    return path.substring(bundlePath.length + 1);
  }
  return path.split('/').pop();
}

function moduleSchema(module, bundleInfo) {
  var parsed;
  try {
    parsed = parseMachO(module.base);
  } catch (e) {
    parsed = { valid: false, encrypted: false, encryption: null, segments: [], machoType: null };
  }
  var bundlePath = bundleInfo.bundlePath || '';
  var inBundle = bundlePath && module.path.indexOf(bundlePath + '/') === 0;
  var rel = inBundle ? relativeToBundle(bundlePath, module.path) : null;
  var isFramework = rel ? rel.indexOf('Frameworks/') === 0 || rel.indexOf('.framework/') !== -1 : false;
  var isExtension = rel ? rel.indexOf('PlugIns/') === 0 || rel.indexOf('.appex/') !== -1 : false;
  var isMain = bundleInfo.executablePath === module.path;
  return {
    name: module.name,
    path: module.path,
    base: module.base.toString(),
    size: module.size,
    isAppModule: Boolean(inBundle),
    isMain: Boolean(isMain),
    isFramework: Boolean(isFramework),
    isExtension: Boolean(isExtension),
    encrypted: Boolean(parsed.encrypted),
    encryption: parsed.encryption,
    machoType: parsed.machoType === null ? null : String(parsed.machoType),
    relativePath: rel
  };
}

function enumerateAppModules() {
  var bundleInfo = getBundleInfo();
  return enumerateModulesCompat()
    .map(function (module) {
      return moduleSchema(module, bundleInfo);
    })
    .filter(function (module) {
      return module.isAppModule;
    });
}

function ownProperties(object, propertyName) {
  try {
    var value = object[propertyName];
    if (!value) {
      return [];
    }
    return value.map(function (item) {
      return item.toString();
    });
  } catch (_) {
    return [];
  }
}

function readCStringPointer(ptrValue) {
  if (!ptrValue || ptrValue.isNull()) {
    return null;
  }
  try {
    return ptrValue.readUtf8String();
  } catch (_) {
    return null;
  }
}

function basename(path) {
  if (!path) {
    return null;
  }
  var parts = path.split('/');
  return parts[parts.length - 1];
}

function classSchema(className) {
  var cls = ObjC.classes[className];
  var superclass = null;
  try {
    superclass = cls.$superClass ? cls.$superClass.$className : null;
  } catch (_) {}

  var moduleName = null;
  try {
    moduleName = cls.$moduleName ? cls.$moduleName.toString() : null;
  } catch (_) {}

  return {
    name: className,
    superclass: superclass,
    moduleName: moduleName,
    protocols: ownProperties(cls, '$protocols'),
    methods: ownProperties(cls, '$ownMethods')
  };
}

function methodSchemasNative(cls, prefix) {
  var classCopyMethodList = native('class_copyMethodList', 'pointer', ['pointer', 'pointer']);
  var methodGetName = native('method_getName', 'pointer', ['pointer']);
  var selGetName = native('sel_getName', 'pointer', ['pointer']);
  var freeFn = native('free', 'void', ['pointer']);
  var countPtr = Memory.alloc(4);
  countPtr.writeU32(0);
  var list = classCopyMethodList(cls, countPtr);
  if (list.isNull()) {
    return [];
  }
  var methods = [];
  var count = countPtr.readU32();
  for (var i = 0; i < count; i++) {
    var method = list.add(i * Process.pointerSize).readPointer();
    var selector = methodGetName(method);
    var name = readCStringPointer(selGetName(selector));
    if (name) {
      methods.push(prefix + ' ' + name);
    }
  }
  freeFn(list);
  return methods;
}

function protocolSchemasNative(cls) {
  var classCopyProtocolListPtr = findExport('class_copyProtocolList');
  var protocolGetNamePtr = findExport('protocol_getName');
  if (!classCopyProtocolListPtr || !protocolGetNamePtr) {
    return [];
  }
  var classCopyProtocolList = native('class_copyProtocolList', 'pointer', ['pointer', 'pointer']);
  var protocolGetName = native('protocol_getName', 'pointer', ['pointer']);
  var freeFn = native('free', 'void', ['pointer']);
  var countPtr = Memory.alloc(4);
  countPtr.writeU32(0);
  var list = classCopyProtocolList(cls, countPtr);
  if (list.isNull()) {
    return [];
  }
  var protocols = [];
  var count = countPtr.readU32();
  for (var i = 0; i < count; i++) {
    var proto = list.add(i * Process.pointerSize).readPointer();
    var name = readCStringPointer(protocolGetName(proto));
    if (name) {
      protocols.push(name);
    }
  }
  freeFn(list);
  return protocols;
}

function classImagePathNative(cls) {
  var dladdrPtr = findExport('dladdr');
  if (!dladdrPtr) {
    return null;
  }
  var dladdr = native('dladdr', 'int', ['pointer', 'pointer']);
  var info = Memory.alloc(Process.pointerSize * 4);
  if (dladdr(cls, info) === 0) {
    return null;
  }
  return readCStringPointer(info.readPointer());
}

function enumerateObjCClassesNative(moduleNames) {
  var objcGetClassListPtr = findExport('objc_getClassList');
  if (!objcGetClassListPtr) {
    return {
      available: false,
      reason: 'Objective-C runtime APIs are unavailable.',
      classes: []
    };
  }

  var moduleFilter = {};
  var hasFilter = false;
  if (moduleNames) {
    for (var i = 0; i < moduleNames.length; i++) {
      moduleFilter[moduleNames[i]] = true;
      hasFilter = true;
    }
  }

  var objcGetClassList = native('objc_getClassList', 'int', ['pointer', 'int']);
  var classGetName = native('class_getName', 'pointer', ['pointer']);
  var classGetSuperclass = native('class_getSuperclass', 'pointer', ['pointer']);
  var objectGetClass = native('object_getClass', 'pointer', ['pointer']);
  var count = objcGetClassList(NULL, 0);
  if (count <= 0) {
    return { available: true, source: 'objc-runtime-c', classes: [] };
  }

  var list = Memory.alloc(count * Process.pointerSize);
  var actual = objcGetClassList(list, count);
  var classes = [];
  var maxClasses = 20000;
  for (var i = 0; i < actual; i++) {
    var cls = list.add(i * Process.pointerSize).readPointer();
    var className = readCStringPointer(classGetName(cls));
    if (!className) {
      continue;
    }

    var imagePath = classImagePathNative(cls);
    var moduleName = basename(imagePath);
    if (hasFilter && moduleFilter[moduleName] !== true && moduleFilter[imagePath] !== true) {
      continue;
    }

    var superclass = classGetSuperclass(cls);
    var superclassName = superclass.isNull() ? null : readCStringPointer(classGetName(superclass));
    var methods = methodSchemasNative(cls, '-');
    var metaclass = objectGetClass(cls);
    if (!metaclass.isNull()) {
      methods = methods.concat(methodSchemasNative(metaclass, '+'));
    }
    classes.push({
      name: className,
      superclass: superclassName,
      moduleName: moduleName,
      imagePath: imagePath,
      protocols: protocolSchemasNative(cls),
      methods: methods
    });
    if (classes.length >= maxClasses) {
      break;
    }
  }

  classes.sort(function (a, b) {
    return a.name.localeCompare(b.name);
  });
  return {
    available: true,
    source: 'objc-runtime-c',
    truncated: classes.length >= maxClasses,
    classes: classes
  };
}

function enumerateObjCClasses(moduleNames) {
  if (!tryLoadObjC()) {
    return enumerateObjCClassesNative(moduleNames);
  }

  var moduleFilter = {};
  var hasFilter = false;
  if (moduleNames) {
    for (var i = 0; i < moduleNames.length; i++) {
      moduleFilter[moduleNames[i]] = true;
      hasFilter = true;
    }
  }

  var names = Object.keys(ObjC.classes).sort();
  var classes = [];
  var maxClasses = 20000;
  for (var j = 0; j < names.length; j++) {
    var payload;
    try {
      payload = classSchema(names[j]);
    } catch (_) {
      continue;
    }
    if (hasFilter && payload.moduleName && moduleFilter[payload.moduleName] !== true) {
      continue;
    }
    if (hasFilter && !payload.moduleName) {
      continue;
    }
    classes.push(payload);
    if (classes.length >= maxClasses) {
      break;
    }
  }

  return {
    available: true,
    truncated: classes.length >= maxClasses,
    classes: classes
  };
}

function ensureDir(path) {
  if (!path || path === '/') {
    return true;
  }
  var mkdir = native('mkdir', 'int', ['pointer', 'int']);
  var current = '';
  var parts = path.split('/');
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) {
      current = '/';
      continue;
    }
    current = current === '/' ? '/' + parts[i] : current + '/' + parts[i];
    mkdir(allocStr(current), 493);
  }
  return true;
}

function copyFileSlice(inputPath, outputPath, offset, size) {
  ensureDir(outputPath.split('/').slice(0, -1).join('/'));
  var input = new File(inputPath, 'rb');
  var output = new File(outputPath, 'wb');
  input.seek(offset, File.SEEK_SET);
  var remaining = size;
  var chunkSize = 1024 * 1024;
  while (remaining > 0) {
    var readSize = Math.min(chunkSize, remaining);
    var data = input.readBytes(readSize);
    if (!data || data.byteLength === 0) {
      break;
    }
    output.write(data);
    remaining -= data.byteLength;
  }
  output.flush();
  output.close();
  input.close();
}

function getFileSize(path) {
  var file = new File(path, 'rb');
  file.seek(0, File.SEEK_END);
  var size = file.tell();
  file.close();
  return size;
}

function readFilePrefix(path, size) {
  var file = new File(path, 'rb');
  var data = file.readBytes(size);
  file.close();
  return new Uint8Array(data);
}

function readU32BE(bytes, offset) {
  return (
    (bytes[offset] * 0x1000000) +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  ) >>> 0;
}

function readU64BE(bytes, offset) {
  var high = readU32BE(bytes, offset);
  var low = readU32BE(bytes, offset + 4);
  return high * 0x100000000 + low;
}

function resolveFileSlice(module, fileSize) {
  var header = readFilePrefix(module.path, Math.min(fileSize, 4096));
  if (header.length < 4) {
    throw new Error('Original module file is too small: ' + module.path);
  }

  var magic = readU32BE(header, 0);
  if (magic !== 0xcafebabe && magic !== 0xcafebabf) {
    return { offset: 0, size: fileSize, fat: false };
  }

  var is64 = magic === 0xcafebabf;
  var nfatArch = readU32BE(header, 4);
  var entrySize = is64 ? 32 : 20;
  var tableSize = 8 + nfatArch * entrySize;
  if (header.length < tableSize) {
    header = readFilePrefix(module.path, tableSize);
  }

  var currentCpuType = module.base.add(4).readU32();
  var currentCpuSubtype = module.base.add(8).readU32() & 0x00ffffff;
  for (var i = 0; i < nfatArch; i++) {
    var entry = 8 + i * entrySize;
    var cpuType = readU32BE(header, entry);
    var cpuSubtype = readU32BE(header, entry + 4) & 0x00ffffff;
    var sliceOffset = is64 ? readU64BE(header, entry + 8) : readU32BE(header, entry + 8);
    var sliceSize = is64 ? readU64BE(header, entry + 16) : readU32BE(header, entry + 12);
    if (cpuType === currentCpuType && cpuSubtype === currentCpuSubtype) {
      if (sliceOffset + sliceSize > fileSize) {
        throw new Error('Fat Mach-O slice exceeds file bounds for ' + module.path);
      }
      return { offset: sliceOffset, size: sliceSize, fat: true };
    }
  }

  throw new Error('Unable to find matching fat Mach-O slice for ' + module.path);
}

function findModuleByPath(path) {
  var modules = enumerateModulesCompat();
  for (var i = 0; i < modules.length; i++) {
    if (modules[i].path === path || modules[i].name === path) {
      return modules[i];
    }
  }
  return null;
}

function dumpModule(modulePath, outPath) {
  var module = findModuleByPath(modulePath);
  if (!module) {
    throw new Error('Module not found: ' + modulePath);
  }
  var parsed = parseMachO(module.base);
  if (!parsed.valid) {
    throw new Error('Module is not a supported Mach-O image: ' + modulePath);
  }

  var fileSize = getFileSize(module.path);
  var fileSlice = resolveFileSlice(module, fileSize);
  copyFileSlice(module.path, outPath, 0, fileSize);

  if (parsed.encryption && parsed.encryption.cryptsize > 0) {
    var out = new File(outPath, 'r+b');
    var remaining = parsed.encryption.cryptsize;
    var offset = parsed.encryption.cryptoff;
    var chunkSize = 1024 * 1024;
    while (remaining > 0) {
      var readSize = Math.min(chunkSize, remaining);
      var data = module.base.add(offset).readByteArray(readSize);
      out.seek(fileSlice.offset + offset, File.SEEK_SET);
      out.write(data);
      offset += readSize;
      remaining -= readSize;
    }
    out.seek(fileSlice.offset + parsed.encryption.cryptidFileOffset, File.SEEK_SET);
    out.write(new Uint8Array([0, 0, 0, 0]).buffer);
    out.flush();
    out.close();
  }

  sendEvent('dumped-module', { module: modulePath, outPath: outPath });
  return {
    outPath: outPath,
    originalPath: module.path,
    name: module.name,
    size: fileSize,
    sliceOffset: fileSlice.offset,
    fat: fileSlice.fat,
    encryption: parsed.encryption
  };
}

function statPath(path) {
  if (tryLoadObjC()) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var isDirPtr = Memory.alloc(1);
    isDirPtr.writeU8(0);
    var exists = fm.fileExistsAtPath_isDirectory_(path, isDirPtr);
    if (!exists) {
      return { exists: false, isDir: false, size: 0 };
    }
    var isDir = isDirPtr.readU8() !== 0;
    var size = 0;
    if (!isDir) {
      var f = new File(path, 'rb');
      f.seek(0, File.SEEK_END);
      size = f.tell();
      f.close();
    }
    return { exists: true, isDir: isDir, size: size };
  }

  var access = native('access', 'int', ['pointer', 'int']);
  if (access(allocStr(path), 0) !== 0) {
    return { exists: false, isDir: false, size: 0 };
  }
  if (isDirectoryPosix(path)) {
    return { exists: true, isDir: true, size: 0 };
  }
  var file = new File(path, 'rb');
  file.seek(0, File.SEEK_END);
  var fallbackSize = file.tell();
  file.close();
  return { exists: true, isDir: false, size: fallbackSize };
}

function isDirectoryPosix(path) {
  var opendir = native('opendir', 'pointer', ['pointer']);
  var closedir = native('closedir', 'int', ['pointer']);
  var dirp = opendir(allocStr(path));
  if (dirp.isNull()) {
    return false;
  }
  closedir(dirp);
  return true;
}

function listDirPosix(path) {
  var opendir = native('opendir', 'pointer', ['pointer']);
  var readdir = native('readdir', 'pointer', ['pointer']);
  var closedir = native('closedir', 'int', ['pointer']);
  var dirp = opendir(allocStr(path));
  if (dirp.isNull()) {
    throw new Error('Unable to open directory: ' + path);
  }

  var entries = [];
  var offsets = getDirentOffsets();
  while (true) {
    var ent = readdir(dirp);
    if (ent.isNull()) {
      break;
    }
    var nameLen = ent.add(offsets.namlen).readU16();
    var name = ent.add(offsets.name).readUtf8String(nameLen);
    if (!name || name === '.' || name === '..') {
      continue;
    }
    entries.push({
      name: name,
      dtype: ent.add(offsets.dtype).readU8()
    });
  }
  closedir(dirp);
  return entries;
}

function listFilesObjC(rootPath) {
  var fm = ObjC.classes.NSFileManager.defaultManager();
  var enumerator = fm.enumeratorAtPath_(rootPath);
  var files = [];
  var dirs = [];
  var item;
  while ((item = enumerator.nextObject()) !== null) {
    var rel = item.toString();
    var full = rootPath + '/' + rel;
    var isDirPtr = Memory.alloc(1);
    isDirPtr.writeU8(0);
    fm.fileExistsAtPath_isDirectory_(full, isDirPtr);
    if (isDirPtr.readU8() !== 0) {
      dirs.push(rel);
    } else {
      files.push(rel);
    }
  }
  return { files: files, dirs: dirs };
}

function listFilesPosix(rootPath) {
  var files = [];
  var dirs = [];
  var maxEntries = 200000;

  function walk(currentPath, relBase) {
    var entries = listDirPosix(currentPath);
    for (var i = 0; i < entries.length; i++) {
      if (files.length + dirs.length > maxEntries) {
        throw new Error('Directory listing exceeded safety limit for ' + rootPath);
      }
      var entry = entries[i];
      var rel = relBase ? relBase + '/' + entry.name : entry.name;
      var full = currentPath + '/' + entry.name;

      if (entry.dtype === DT_DIR || (entry.dtype === DT_UNKNOWN && isDirectoryPosix(full))) {
        dirs.push(rel);
        walk(full, rel);
      } else {
        files.push(rel);
      }
    }
  }

  walk(rootPath, '');
  return { files: files, dirs: dirs };
}

function listFiles(rootPath) {
  if (tryLoadObjC()) {
    return listFilesObjC(rootPath);
  }
  return listFilesPosix(rootPath);
}

function readFile(path, offset, size) {
  var file = new File(path, 'rb');
  file.seek(offset, File.SEEK_SET);
  var data = file.readBytes(size);
  file.close();
  return data;
}

function removePath(path) {
  if (tryLoadObjC()) {
    ObjC.classes.NSFileManager.defaultManager().removeItemAtPath_error_(path, NULL);
    return true;
  }
  var unlink = native('unlink', 'int', ['pointer']);
  return unlink(allocStr(path)) === 0;
}

rpc.exports = {
  getbundleinfo: getBundleInfo,
  enumeratemodules: enumerateAppModules,
  enumerateobjcclasses: enumerateObjCClasses,
  dumpmodule: dumpModule,
  getgroupcontainers: getGroupContainers,
  statpath: statPath,
  listfiles: listFiles,
  readfile: readFile,
  removepath: removePath,
  ensuredir: ensureDir
};
