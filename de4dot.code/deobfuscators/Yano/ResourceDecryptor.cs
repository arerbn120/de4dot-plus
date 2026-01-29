using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;

namespace de4dot.code.deobfuscators.Yano
{
    class ResourceDecryptor
    {
        private readonly ModuleDefMD module;
        private readonly StringDecryptor strDecryptor;

        private string? resourceName;
        private long key1 = -1;
        private long key2 = -1;
        private readonly List<MethodDef> toRemove = new();
        private Instruction? toRemoveInstr;

        public ResourceDecryptor(ModuleDefMD module, StringDecryptor strDec)
        {
            this.module = module ?? throw new ArgumentNullException(nameof(module));
            strDecryptor = strDec ?? throw new ArgumentNullException(nameof(strDec));
        }

        public IReadOnlyList<MethodDef> ToRemove => toRemove;
        public Instruction? ToRemoveCall => toRemoveInstr;
        public bool Detected => !string.IsNullOrEmpty(resourceName) && key1 != -1 && key2 != -1;
        public string? Name => resourceName;

        public void Find()
        {
            var moduleCtor = DotNetUtils.GetModuleTypeCctor(module);
            if (moduleCtor is null || !moduleCtor.HasBody)
                return;

            foreach (var inst in moduleCtor.Body.Instructions)
            {
                if (inst.OpCode != OpCodes.Call || inst.Operand is not MethodDef method || !method.HasBody)
                    continue;

                var instr2 = method.Body.Instructions;
                if (instr2.Count < 5) continue;

                if (instr2[0].OpCode != OpCodes.Call ||
                    instr2[1].OpCode != OpCodes.Ldnull ||
                    instr2[2].OpCode != OpCodes.Ldftn ||
                    instr2[3].OpCode != OpCodes.Newobj ||
                    instr2[4].OpCode != OpCodes.Callvirt)
                    continue;

                if (instr2[2].Operand is not MethodDef method2 || !method2.HasBody)
                    continue;

                if (strDecryptor.Detected)
                    strDecryptor.DecryptMethod(method2);

                var instr3 = method2.Body.Instructions;
                resourceName = DotNetUtils.FindInstruction(instr3, OpCodes.Ldstr, 0)?.Operand?.ToString();
                key1 = (long)(DotNetUtils.FindInstruction(instr3, OpCodes.Ldc_I8, 0)?.Operand ?? -1);
                key2 = (long)(DotNetUtils.FindInstruction(instr3, OpCodes.Ldc_I8, 1)?.Operand ?? -1);

                toRemoveInstr = inst;
                toRemove.Add(method);
                toRemove.Add(method2);
            }
        }

        public void FixResources()
        {
            var decrypted = DecryptRes();
            if (decrypted is null || decrypted.Length == 0)
                return;

            try
            {
                var asm = AssemblyDef.Load(decrypted);
                foreach (var resource in asm.ManifestModule.Resources)
                {
                    if (resource is EmbeddedResource embedded)
                        module.Resources.Add(embedded);
                }
            }
            catch
            {
                // If blob isn't a valid assembly, ignore silently
            }
        }

        private byte[]? DecryptRes()
        {
            if (string.IsNullOrEmpty(resourceName))
                return null;

            if (DotNetUtils.GetResource(module, resourceName!) is not object res)
                return null;

            var rawData = GetEmbeddedResourceData(res);
            if (rawData == null)
                return null;

            using var manifestResourceStream = new MemoryStream(rawData);

            try
            {
                using var des = new DESCryptoServiceProvider();
                var keyBytes = BitConverter.GetBytes((ulong)key1);
                var ivBytes = BitConverter.GetBytes((ulong)key2);

                using var decryptor = des.CreateDecryptor(keyBytes, ivBytes);
                using var cryptoStream = new CryptoStream(manifestResourceStream, decryptor, CryptoStreamMode.Read);
                using var deflateStream = new DeflateStream(cryptoStream, CompressionMode.Decompress);
                using var ms = new MemoryStream();

                deflateStream.CopyTo(ms);
                return ms.ToArray();
            }
            catch
            {
                return null;
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