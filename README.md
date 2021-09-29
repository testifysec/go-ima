# go-ima

Simple too that checks the ima-log to see if a file has been tampered with.

## How to use

1. Set the IMA policy to `tcb` by configuring GRUB  `GRUB_CMDLINE_LINUX="ima_policy=tcb ima_hash=sha256 ima=on"`
2. Compile
3. Run

```
./go-ima {file to check}
```

You will get an exit status of 0 if the file has not been modified since inception or boot.  If you get an Exit status of zero id means the IMA log contains at least one hash that does not match what is on disk.  This could either be the sign of an attack, or somebody editing files.

