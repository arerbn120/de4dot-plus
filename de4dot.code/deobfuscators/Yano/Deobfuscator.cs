/*
    Copyright (C) 2016 TheProxy

    This file is part of modified de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    de4dot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with de4dot.  If not, see <http://www.gnu.org/licenses/>.
*/

#nullable enable

using de4dot.blocks;
using dnlib.DotNet;
using System;
using System.Collections.Generic;

namespace de4dot.code.deobfuscators.Yano
{
    public class DeobfuscatorInfo : DeobfuscatorInfoBase
    {
        public const string THE_NAME = "Yano";
        public const string THE_TYPE = "yn";
        private const string DEFAULT_REGEX = @"!^[a-zA-Z1-9]{1,4}$" + DeobfuscatorBase.DEFAULT_VALID_NAME_REGEX;

        public DeobfuscatorInfo() : base(DEFAULT_REGEX) { }

        public override string Name => THE_NAME;
        public override string Type => THE_TYPE;

        public override IDeobfuscator CreateDeobfuscator() =>
            new Deobfuscator(new Deobfuscator.Options
            {
                RenameResourcesInCode = false,
                ValidNameRegex = validNameRegex.Get(),
            });

        class Deobfuscator : DeobfuscatorBase
        {
            private bool foundAttribute;
            private string version = string.Empty;
            private ResourceDecryptor? resDecryptor;
            private StringDecryptor? strDecryptor;

            internal class Options : OptionsBase { }

            public Deobfuscator(Options options) : base(options) { }

            public override string Type => DeobfuscatorInfo.THE_TYPE;
            public override string TypeLong => DeobfuscatorInfo.THE_NAME;
            public override string Name => $"{TypeLong} {version}";

            protected override int DetectInternal()
            {
                int val = 0;
                if (foundAttribute) val = 100;

                if (resDecryptor is not null)
                    val += val < 100 ? Convert.ToInt32(resDecryptor.Detected) * 100 : Convert.ToInt32(resDecryptor.Detected) * 10;

                if (strDecryptor is not null)
                    val += val < 100 ? Convert.ToInt32(strDecryptor.Detected) * 100 : Convert.ToInt32(strDecryptor.Detected) * 10;

                return val;
            }

            protected override void ScanForObfuscator()
            {
                foreach (var type in module.Types)
                {
                    if (type.FullName != "YanoAttribute")
                        continue;

                    foundAttribute = true;
                    foreach (var field in type.Fields)
                    {
                        if (field.Name == "Version" && field.Constant?.Value is string s)
                            version = s;
                    }
                }

                strDecryptor = new StringDecryptor(module);
                strDecryptor.Find();

                resDecryptor = new ResourceDecryptor(module, strDecryptor);
                resDecryptor.Find();
            }

            public override void DeobfuscateBegin()
            {
                base.DeobfuscateBegin();

                if (resDecryptor?.Detected == true)
                    resDecryptor.FixResources();

                if (strDecryptor?.Detected == true && strDecryptor.Method is not null)
                {
                    staticStringInliner.Add(
                        strDecryptor.Method,
                        (method, gim, args) => strDecryptor.Decrypt((string)args[0], (int)args[1])
                    );
                }
            }

            public override void DeobfuscateEnd()
            {
                if (resDecryptor is not null)
                {
                    if (resDecryptor.ToRemoveCall is not null)
                    {
                        var cctor = DotNetUtils.GetModuleTypeCctor(module);
                        cctor?.Body?.Instructions.Remove(resDecryptor.ToRemoveCall);

                        if (!string.IsNullOrEmpty(resDecryptor.Name))
                        {
                            var res = DotNetUtils.GetResource(module, resDecryptor.Name!);
                            if (res is not null)
                                module.Resources.Remove(res);
                        }
                    }

                    foreach (var method in resDecryptor.ToRemove)
                        method.DeclaringType?.Methods.Remove(method);
                }

                if (strDecryptor?.Detected == true && strDecryptor.Method?.DeclaringType is not null)
                    module.Types.Remove(strDecryptor.Method.DeclaringType);

                base.DeobfuscateEnd();
            }

            public override IEnumerable<int> GetStringDecrypterMethods() => new List<int>();
        }
    }
}
