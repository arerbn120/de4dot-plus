using System;
using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.NetZ
{
    public class DeobfuscatorInfo : DeobfuscatorInfoBase
    {
        public const string THE_NAME = "NetZ";
        public const string THE_TYPE = "nz";
        const string DEFAULT_REGEX = DeobfuscatorBase.DEFAULT_ASIAN_VALID_NAME_REGEX;

        public DeobfuscatorInfo() : base(DEFAULT_REGEX) { }

        public override string Name => THE_NAME;
        public override string Type => THE_TYPE;

        public override IDeobfuscator CreateDeobfuscator()
        {
            return new Deobfuscator(new Deobfuscator.Options
            {
                ValidNameRegex = validNameRegex.Get(),
            });
        }

        protected override IEnumerable<Option> GetOptionsInternal() => new List<Option>();
    }

    class Deobfuscator : DeobfuscatorBase
    {
        readonly Options options;
        bool netPackAttribute;
        ResourceDecrypter resDecryptor;

        internal class Options : OptionsBase
        {
        }

        public override string Type => DeobfuscatorInfo.THE_TYPE;
        public override string TypeLong => DeobfuscatorInfo.THE_NAME;
        public override string Name => TypeLong;

        public Deobfuscator(Options options) : base(options)
        {
            this.options = options ?? throw new ArgumentNullException(nameof(options));
        }

        protected override int DetectInternal()
        {
            var val = 0;
            if (netPackAttribute) val += 10;
            if (resDecryptor?.Detected == true) val += 100;
            return val;
        }

        void FindNetPackAttribute()
        {
            foreach (var type in module.Types)
            {
                if (string.Equals(type?.Namespace, "netz", StringComparison.Ordinal))
                {
                    netPackAttribute = true;
                    break;
                }
            }
        }

        protected override void ScanForObfuscator()
        {
            FindNetPackAttribute();
            resDecryptor = new ResourceDecrypter(module, DeobfuscatedFile);
            resDecryptor.Find();
        }

        public override bool GetDecryptedModule(int count, ref byte[] newFileData, ref DumpedMethods dumpedMethods)
        {
            if (count != 0) return false;
            newFileData = resDecryptor?.Decrypted;
            resDecryptor?.ExtractLibraries();
            return true;
        }

        public override IDeobfuscator ModuleReloaded(ModuleDefMD module)
        {
            var newOne = new Deobfuscator(options);
            newOne.SetModule(module);
            return newOne;
        }

        public override void DeobfuscateBegin() => base.DeobfuscateBegin();

        public override IEnumerable<int> GetStringDecrypterMethods() => Enumerable.Empty<int>();
    }
}
