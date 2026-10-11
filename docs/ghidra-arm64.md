# Headless decompilation on aarch64

`rekit ghidra` and REA's Ghidra provider both drive the same thing: Ghidra's **native
decompiler** binary (`Ghidra/Features/Decompiler/os/<platform>/decompile`). Public Ghidra
releases ship that binary for the major x86 platforms, but not for Linux **aarch64** - so
on an ARM box the Decompiler feature has nothing to execute and headless decompilation
fails even though the Java side of Ghidra runs fine.

## What "not shipped" looks like

```
$ ls Ghidra/Features/Decompiler/os/
linux_x86_64   win_x86_64   ...      # no linux_arm_64
```

The Java analysis, the Sleigh processors and the whole API work on aarch64. Only the
native decompiler process is missing, which is why people conclude "Ghidra is broken on
ARM" when it is one artifact away from working.

## Build it

Ghidra builds its native components with Gradle; the decompiler natives live in
`Ghidra/Features/Decompiler/buildNatives.gradle` and are exposed as per-platform tasks of
the form `buildNatives_<platform>`. Building the aarch64 decompiler needs a C/C++ toolchain
plus the parser generators (`bison`, `flex`):

```bash
sudo apt-get install -y build-essential bison flex
cd ghidra                      # a source checkout of your release tag
gradle buildNatives_linux_arm_64
```

Then drop the produced executable next to its x86 sibling:

```bash
GHIDRA=/opt/ghidra_12.1.4_PUBLIC
mkdir -p "$GHIDRA/Ghidra/Features/Decompiler/os/linux_arm_64"
cp Ghidra/Features/Decompiler/build/os/linux_arm_64/decompile \
   "$GHIDRA/Ghidra/Features/Decompiler/os/linux_arm_64/decompile"
```

## Verify the artifact is really a native aarch64 build

Never trust a copy step - check the ELF:

```bash
D=$GHIDRA/Ghidra/Features/Decompiler/os
file $D/linux_arm_64/decompile
# ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, not stripped
ls -l $D/linux_arm_64/ $D/linux_x86_64/     # mtimes should differ from the release zip
```

In this stack the check passes and decompilation runs at native speed: an aarch64
`decompile` of 4,100,768 bytes [calc: `stat -c %s` on the built binary] with BuildID
`48e6bdead2959b05761177ffdee2d70811a2673f` [calc: `file` output], sitting in a directory
created after the release unzip (release files: Sep 21 16:38, our arm64 artifact: Oct 6
22:58 [calc: `ls -l`]).

## End-to-end proof

With the binary in place, both layers decompile on aarch64. The strongest check is a hash
comparison across surfaces - the same file must yield the same identity no matter which
layer opened it:

```bash
rekit.py triage  /usr/bin/ls --json | jq -r .sha256      # sha256 via rekit
# REA open_binary on the same path returns the same sha256 and reports arch=arm64
```

`tests/run_rekit_suite.sh` runs the `ghidra_decompile` check against the in-repo aarch64
fixture on every invocation, so a regression (a wiped `os/` directory after an upgrade)
fails the suite instead of failing silently at analysis time.

## Notes

* Only `decompile` is needed to analyze existing architectures; `sleigh` is used when
  compiling new processor specifications.
* Re-check after every Ghidra upgrade: a fresh unzip restores the x86-only `os/` directory.
* If your Ghidra already ships `linux_arm_64`, skip the build and just verify with `file`.
