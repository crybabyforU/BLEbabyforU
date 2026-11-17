# Scripts named by function

These are optional relative symlinks to the real scripts. The name is
`<number>__<two-word-function>`, matching `./run-all-ble.sh -l`.

The real files keep their original names so the framework behaves exactly
like the lab. For normal use, run the number instead:

```bash
./run-all-ble.sh -N 2
```

That lets the runner set the correct working directory, timeout, hardware
check and Python path. Running some tool symlinks directly (SweynTooth,
Sniffle, Zephyr) can fail because those scripts expect their own directory.
