import com.reandroid.apk.ApkBundle;
import com.reandroid.apk.ApkModule;
import com.reandroid.apk.ApkSplitInfoCleaner;
import com.reandroid.app.AndroidManifest;
import com.reandroid.archive.writer.ZipAligner;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import com.reandroid.arsc.value.ValueType;
import com.reandroid.arsc.value.ValueItem;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * QuettaClone — mirrors BFE's ApkRewriter exactly.
 *
 * Uses ARSCLib's Java API directly (no XML decode/rebuild), so the binary
 * manifest and resources.arsc are patched in-place — exactly what BFE does.
 *
 * Usage:
 *   java -cp APKEditor.jar:QuettaClone.jar QuettaClone <input.xapk|input.apk> <output.apk> <newPackage> <label>
 */
public class QuettaClone {

    static final int ID_sharedUserId = 0x0101000b;
    static final int ID_permission = 0x01010006;
    static final int ID_readPermission = 0x01010007;
    static final int ID_writePermission = 0x01010008;
    static final int ID_permissionGroup = 0x0101000a;
    static final int ID_taskAffinity = 0x01010012;
    static final int ID_sharedUserLabel = 0x01010261;
    static final int ID_sharedUserMaxSdkVersion = 0x01010620;

    static final String[] COMPONENT_TAGS = {
        AndroidManifest.TAG_application, AndroidManifest.TAG_activity,
        AndroidManifest.TAG_activity_alias, AndroidManifest.TAG_service,
        AndroidManifest.TAG_receiver, AndroidManifest.TAG_provider
    };
    static final String[] PERMISSION_DECL_TAGS = {
        AndroidManifest.TAG_permission, "permission-group", "permission-tree",
        AndroidManifest.TAG_uses_permission, "uses-permission-sdk-23"
    };

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: QuettaClone <input.xapk|input.apk> <output.apk> <newPackage> <label>");
            System.exit(1);
        }
        File input = new File(args[0]);
        File output = new File(args[1]);
        String newPkg = args[2];
        String label = args[3];

        System.out.println("Input   : " + input);
        System.out.println("Output  : " + output);
        System.out.println("Package : " + newPkg);
        System.out.println("Label   : " + label);
        System.out.println();

        ApkModule module;
        String oldPkg;

        String name = input.getName().toLowerCase();
        if (name.endsWith(".xapk") || name.endsWith(".apks") || name.endsWith(".apkm") || name.endsWith(".zip")) {
            System.out.println("[1/8] Merging split APKs...");
            ZipFile zf = new ZipFile(input);
            File tmpDir = File.createTempFile("clone_", "");
            tmpDir.delete();
            tmpDir.mkdir();
            java.util.Enumeration<? extends ZipEntry> entries = zf.entries();
            List<File> apks = new ArrayList<>();
            File baseApk = null;
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                if (ze.getName().endsWith(".apk")) {
                    File out = new File(tmpDir, new File(ze.getName()).getName());
                    try (java.io.InputStream is = zf.getInputStream(ze);
                         java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = is.read(buf)) > 0) fos.write(buf, 0, n);
                    }
                    if (ze.getName().toLowerCase().contains("base") || ze.getName().equals("net.quetta.browser.apk")) {
                        baseApk = out;
                    } else {
                        apks.add(out);
                    }
                }
            }
            zf.close();
            if (baseApk == null && !apks.isEmpty()) baseApk = apks.remove(0);

            ApkBundle bundle = new ApkBundle();
            bundle.addModule(ApkModule.loadApkFile(baseApk, "base"));
            for (File s : apks) bundle.addModule(ApkModule.loadApkFile(s, s.getName().replace(".apk", "")));
            module = bundle.mergeModules();
            ApkSplitInfoCleaner.cleanSplitInfo(module);
            for (File f : tmpDir.listFiles()) f.delete();
            tmpDir.delete();
        } else {
            System.out.println("[1/8] Loading single APK...");
            module = ApkModule.loadApkFile(input);
        }

        AndroidManifestBlock manifest = module.getAndroidManifest();
        if (manifest == null) throw new IOException("No AndroidManifest.xml");
        oldPkg = manifest.getPackageName();
        if (oldPkg == null) throw new IOException("Manifest has no package");
        System.out.println("  Old package: " + oldPkg);

        renamePackage(module, manifest, oldPkg, newPkg);

        System.out.println("[6/8] Setting app label...");
        manifest.setApplicationLabel(label);
        ResXmlElement mainActivity = manifest.getMainActivity();
        if (mainActivity != null) {
            ValueItem labelAttr = mainActivity.searchAttributeByResourceId(AndroidManifest.ID_label);
            if (labelAttr != null) {
                labelAttr.setValueAsString(label);
            }
        }

        System.out.println("[7/8] Writing APK...");
        module.setApkSignatureBlock(null);
        manifest.refreshFull();
        if (module.hasTableBlock()) module.getTableBlock().refresh();

        output.getParentFile().mkdirs();
        if (output.exists()) output.delete();

        com.reandroid.archive.writer.ApkFileWriter writer = module.createApkFileWriter(output);
        ZipAligner aligner = new ZipAligner();
        aligner.setDefaultAlignment(4);
        aligner.setFileAlignment(new Predicate<String>() {
            public boolean test(String n) { return n.startsWith("lib/") && n.endsWith(".so"); }
        }, 4096);
        writer.setZipAligner(aligner);
        writer.setApkSignatureBlock(null);
        writer.write();
        writer.close();
        module.close();

        System.out.println("[8/8] Done: " + output);
    }

    static void renamePackage(ApkModule module, AndroidManifestBlock manifest,
                              String oldPkg, String newPkg) throws IOException {
        ResXmlElement app = manifest.getApplicationElement();
        ResXmlElement manifestEl = manifest.getManifestElement();
        if (manifestEl == null) throw new IOException("Manifest has no <manifest> element");

        if (app != null) {
            List<ResXmlElement> elements = new ArrayList<>();
            elements.add(app);
            java.util.Iterator<ResXmlElement> it1 = app.recursiveElements();
            while (it1.hasNext()) elements.add(it1.next());

            // 1. Absolute-ize relative component class names BEFORE the rename
            int absolutized = 0;
            for (ResXmlElement el : elements) {
                if (!isComponentTag(el.getName())) continue;
                for (int id : new int[]{AndroidManifest.ID_name, AndroidManifest.ID_targetActivity}) {
                    ValueItem a = el.searchAttributeByResourceId(id);
                    if (a == null || a.getValueType() != ValueType.STRING) continue;
                    String v = a.getValueAsString();
                    if (v == null) continue;
                    String abs = absoluteClassName(v, oldPkg);
                    if (abs == null) continue;
                    a.setValueAsString(abs);
                    absolutized++;
                }
            }
            if (absolutized > 0)
                System.out.println("  Made " + absolutized + " relative class name(s) absolute");

            // 2. Provider authorities
            int authCount = 0;
            for (ResXmlElement p : manifest.listApplicationElementsByTag(AndroidManifest.TAG_provider)) {
                ValueItem a = p.searchAttributeByResourceId(AndroidManifest.ID_authorities);
                if (a == null || a.getValueType() != ValueType.STRING) continue;
                String old = a.getValueAsString();
                if (old == null) continue;
                String[] parts = old.split(";");
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < parts.length; i++) {
                    if (i > 0) sb.append(";");
                    String t = parts[i].trim();
                    if (t.isEmpty()) { sb.append(t); continue; }
                    if (t.equals(oldPkg)) sb.append(newPkg);
                    else if (t.startsWith(oldPkg + ".")) sb.append(newPkg).append(t.substring(oldPkg.length()));
                    else sb.append(newPkg).append(".").append(t);
                }
                String renamed = sb.toString();
                if (!renamed.equals(old)) {
                    a.setValueAsString(renamed);
                    authCount++;
                }
            }
            if (authCount > 0)
                System.out.println("  Re-prefixed " + authCount + " provider authorities");

            // 3b. Permission references on components
            int permRefs = 0;
            for (ResXmlElement el : elements) {
                for (int id : new int[]{ID_permission, ID_readPermission, ID_writePermission}) {
                    ValueItem a = el.searchAttributeByResourceId(id);
                    if (a == null || a.getValueType() != ValueType.STRING) continue;
                    String v = a.getValueAsString();
                    if (v == null) continue;
                    if (v.startsWith(oldPkg + ".")) {
                        a.setValueAsString(newPkg + v.substring(oldPkg.length()));
                        permRefs++;
                    }
                }
            }
            if (permRefs > 0)
                System.out.println("  Re-prefixed " + permRefs + " permission references");

            // 5. taskAffinity
            int affinities = 0;
            for (ResXmlElement el : elements) {
                ValueItem a = el.searchAttributeByResourceId(ID_taskAffinity);
                if (a == null || a.getValueType() != ValueType.STRING) continue;
                String v = a.getValueAsString();
                if (v == null) continue;
                String nv;
                if (v.equals(oldPkg)) nv = newPkg;
                else if (v.startsWith(oldPkg + ".")) nv = newPkg + v.substring(oldPkg.length());
                else continue;
                a.setValueAsString(nv);
                affinities++;
            }
            if (affinities > 0)
                System.out.println("  Re-prefixed " + affinities + " taskAffinity values");
        }

        // 3a. Permission declarations at manifest level
        int permDecls = 0;
        List<ResXmlElement> allElements = new ArrayList<>();
        java.util.Iterator<ResXmlElement> it2 = manifestEl.recursiveElements();
        while (it2.hasNext()) allElements.add(it2.next());
        for (ResXmlElement el : allElements) {
            if (!isPermissionDeclTag(el.getName())) continue;
            for (int id : new int[]{AndroidManifest.ID_name, ID_permissionGroup}) {
                ValueItem a = el.searchAttributeByResourceId(id);
                if (a == null || a.getValueType() != ValueType.STRING) continue;
                String v = a.getValueAsString();
                if (v == null) continue;
                if (v.startsWith(oldPkg + ".")) {
                    a.setValueAsString(newPkg + v.substring(oldPkg.length()));
                    permDecls++;
                }
            }
        }
        if (permDecls > 0)
            System.out.println("  Re-prefixed " + permDecls + " permission declarations");

        // 4. Drop sharedUserId
        ValueItem shared = manifestEl.searchAttributeByResourceId(ID_sharedUserId);
        if (shared != null) {
            manifestEl.removeAttributesWithId(ID_sharedUserId);
            manifestEl.removeAttributesWithId(ID_sharedUserLabel);
            manifestEl.removeAttributesWithId(ID_sharedUserMaxSdkVersion);
            System.out.println("  Dropped sharedUserId");
        }

        // 6. THE KEY STEP: setPackageName renames BOTH manifest AND resources.arsc
        System.out.println("  Renaming package: " + oldPkg + " -> " + newPkg + " (manifest + resources.arsc)");
        module.setPackageName(newPkg);
    }

    static boolean isComponentTag(String name) {
        for (String t : COMPONENT_TAGS) if (t.equals(name)) return true;
        return false;
    }

    static boolean isPermissionDeclTag(String name) {
        for (String t : PERMISSION_DECL_TAGS) if (t.equals(name)) return true;
        return false;
    }

    static String absoluteClassName(String name, String pkg) {
        if (name == null || name.isEmpty()) return null;
        if (name.startsWith(".")) return pkg + name;
        if (!name.contains(".")) return pkg + "." + name;
        return null;
    }
}
