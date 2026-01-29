using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Resources;
using System.Reflection;
using System.IO.Compression;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using de4dot.blocks;

namespace de4dot.code.deobfuscators.NetZ
{
    class ResourceDecrypter
    {
        ModuleDefMD module;
        MethodDef resourceDecryptor;
        IDeobfuscatedFile deobfuscator;
        byte[] decryptedBytes;
        List<DictionaryEntry> libraries = new List<DictionaryEntry>();

        public bool Detected => resourceDecryptor != null;
        public byte[] Decrypted => decryptedBytes;

        public ResourceDecrypter(ModuleDefMD module, IDeobfuscatedFile deobfuscator)
        {
            this.module = module ?? throw new ArgumentNullException(nameof(module));
            this.deobfuscator = deobfuscator ?? throw new ArgumentNullException(nameof(deobfuscator));
        }

        public void Find()
        {
            var entrypoint = module.EntryPoint;
            if (entrypoint == null || !entrypoint.HasBody)
                return;

            var instr = entrypoint.Body.Instructions;
            for (int i = 0; i < instr.Count - 1; i++)
            {
                if (instr[i].OpCode != OpCodes.Call)
                    continue;

                if (!(instr[i].Operand is MethodDef mtd))
                    continue;

                if (mtd.Signature.ToString() != "System.Int32 (System.String[])")
                    continue;

                var mtdInstr = mtd.Body.Instructions;
                var inst = DotNetUtils.FindInstruction(mtdInstr, OpCodes.Ldstr, 0);
                if (inst == null)
                    continue;

                int callIndex = -1;
                for (int k = 0; k < mtdInstr.Count; k++)
                {
                    if (mtdInstr[k] == inst) { callIndex = k; break; }
                }
                if (callIndex < 0)
                    continue;

                if (callIndex + 1 >= mtdInstr.Count || mtdInstr[callIndex + 1].OpCode != OpCodes.Call)
                    continue;

                var mtdGetRes = mtdInstr[callIndex + 1].Operand as MethodDef;
                if (mtdGetRes == null)
                    continue;

                if (mtdGetRes.Signature.ToString() != "System.Byte[] (System.String)")
                    continue;

                var inst2 = DotNetUtils.FindInstruction(mtdGetRes.Body.Instructions, OpCodes.Ldstr, 0);
                if (inst2 == null)
                    continue;

                var resName = inst2.Operand.ToString() + ".resources";
                var embedded = DotNetUtils.GetResource(module, resName) as object;
                if (embedded == null)
                    continue;

                byte[]? rawResources;
                try
                {
                    rawResources = GetEmbeddedResourceData(embedded);
                }
                catch
                {
                    continue;
                }
                if (rawResources == null)
                    continue;

                using (var ms = new MemoryStream(rawResources))
                using (var rr = new ResourceReader(ms))
                {
                    var e = rr.GetEnumerator();
                    while (e.MoveNext())
                    {
                        var entry = (DictionaryEntry)e.Entry;
                        var key = entry.Key?.ToString();
                        if (key == null)
                            continue;

                        if (key == inst.Operand.ToString())
                        {
                            decryptedBytes = UnZip(entry.Value as byte[]);
                        }
                        else if (key != "zip.dll")
                        {
                            libraries.Add(entry);
                        }
                    }
                }

                return;
            }
        }

        public void ExtractLibraries()
        {
            if (libraries.Count == 0)
                return;

            foreach (var res in libraries)
            {
                string key = res.Key?.ToString() ?? string.Empty;
                string realName = key.Split(new[] { "!2!1" }, StringSplitOptions.None)[0];
                byte[] decrypted = UnZip(res.Value as byte[]);
                if (decrypted != null)
                    deobfuscator.CreateAssemblyFile(decrypted, realName, null);
            }
        }

        private static byte[] UnZip(byte[] data)
        {
            if (data == null || data.Length == 0)
                return null;

            using (var input = new MemoryStream(data))
            using (var def = new DeflateStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                def.CopyTo(output);
                return output.ToArray();
            }
        }

        // Reflection helper: tries GetResourceData(), GetResourceStream(), Data property/field
        private static byte[]? GetEmbeddedResourceData(object resource)
        {
            if (resource == null) return null;
            var type = resource.GetType();

            var mi = type.GetMethod("GetResourceData", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
            if (mi != null && mi.ReturnType == typeof(byte[]))
            {
                try { return (byte[])mi.Invoke(resource, null); } catch { return null; }
            }

            mi = type.GetMethod("GetResourceStream", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
            if (mi != null && typeof(Stream).IsAssignableFrom(mi.ReturnType))
            {
                try
                {
                    using var s = mi.Invoke(resource, null) as Stream;
                    if (s == null) return null;
                    using var ms = new MemoryStream();
                    s.CopyTo(ms);
                    return ms.ToArray();
                }
                catch { return null; }
            }

            var pi = type.GetProperty("Data", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (pi != null && pi.PropertyType == typeof(byte[]))
            {
                try { return (byte[])pi.GetValue(resource); } catch { return null; }
            }

            var fi = type.GetField("data", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (fi != null && fi.FieldType == typeof(byte[]))
            {
                try { return (byte[])fi.GetValue(resource); } catch { return null; }
            }

            return null;
        }
    }
}