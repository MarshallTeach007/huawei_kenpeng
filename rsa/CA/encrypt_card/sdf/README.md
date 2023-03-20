# sdb-sdf

## Insert module into kernel

```bash
cd kernel-module
insmod PCIE_CCP903T.ko
insmod ntl_crypto.ko
```

## Add `./bin` into `LD_LIBRARY_PATH`

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/bin
```

## Compile `sdb-sdf`

```
make
```
