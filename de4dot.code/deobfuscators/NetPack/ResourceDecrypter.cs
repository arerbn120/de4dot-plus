using System;
using System.IO;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using de4dot.blocks;

namespace de4dot.code.deobfuscators.NetPack
{
    class ResourceDecrypter
    {
        ModuleDefMD module;
        MethodDef resourceDecryptor;
        byte[] decryptedBytes;

        public bool Detected => resourceDecryptor != null;
        public byte[] Decrypted => decryptedBytes;

        public ResourceDecrypter(ModuleDefMD module)
        {
            this.module = module ?? throw new ArgumentNullException(nameof(module));
        }

        public void Find()
        {
            var entrypoint = module.EntryPoint;
            if (entrypoint == null || !entrypoint.HasBody)
                return;

            var instr = entrypoint.Body.Instructions;
            for (int i = 0; i < instr.Count - 1; i++)
            {
                if (instr[i].OpCode != OpCodes.Ldc_I4_0) continue;
                if (instr[i + 1].OpCode != OpCodes.Newarr) continue;
                if (instr[i + 2].OpCode != OpCodes.Stloc_0) continue;
                if (instr[i + 3].OpCode != OpCodes.Call) continue;
                if (instr[i + 4].OpCode != OpCodes.Ldstr) continue;
                if (instr[i + 5].OpCode != OpCodes.Callvirt) continue;
                if (instr[i + 6].OpCode != OpCodes.Stloc_1) continue;
                if (instr[i + 7].OpCode != OpCodes.Ldloc_1) continue;
                if (instr[i + 8].OpCode != OpCodes.Callvirt) continue;
                if (instr[i + 9].OpCode != OpCodes.Conv_Ovf_I) continue;
                if (instr[i + 10].OpCode != OpCodes.Newarr) continue;

                resourceDecryptor = entrypoint;
                decryptedBytes = Decrypt(instr[i + 4].Operand.ToString());
            }
        }

        byte[] Decrypt(string resName)
        {
            // default to empty array if resource lookup fails to preserve original behavior
            byte[] array = new byte[0];
            var resource = DotNetUtils.GetResource(module, resName) as object;
            if (resource == null)
                return array;

            try
            {
                var raw = GetEmbeddedResourceData(resource);
                if (raw != null && raw.Length > 0)
                    array = QuickLZ.decompress(raw);
            }
            catch
            {
                // preserve original behavior: return empty array on error
            }
            return array;
        }

        // Reflection helper: tries GetResourceData(), GetResourceStream(), Data property/field
        private static byte[]? GetEmbeddedResourceData(object resource)
        {
            if (resource == null) return null;
            var type = resource.GetType();

            // Try method GetResourceData() -> byte[]
            var mi = type.GetMethod("GetResourceData", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
            if (mi != null && mi.ReturnType == typeof(byte[]))
            {
                try { return (byte[])mi.Invoke(resource, null); } catch { return null; }
            }

            // Try method GetResourceStream() -> Stream
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

            // Try property Data -> byte[]
            var pi = type.GetProperty("Data", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (pi != null && pi.PropertyType == typeof(byte[]))
            {
                try { return (byte[])pi.GetValue(resource); } catch { return null; }
            }

            // Try field data -> byte[]
            var fi = type.GetField("data", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (fi != null && fi.FieldType == typeof(byte[]))
            {
                try { return (byte[])fi.GetValue(resource); } catch { return null; }
            }

            return null;
        }
    }
}