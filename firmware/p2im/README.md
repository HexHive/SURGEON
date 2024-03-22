# P2IM firmware

The firmware files in this directory were taken from the [Fuzzware](https://github.com/fuzzware-fuzzer/fuzzware/tree/898ba4369623032952ddb817f4ad52850c4b8d80)
repository. We opted for those binaries because the original binaries in the
[P2IM](https://github.com/RiS3-Lab/p2im-real_firmware/tree/d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7)
repository have an AFL forkserver already compiled in.
We want to evaluate against binary-only systems and instrument the binary via
our static binary rewriter, which then adds the forkserver for us.

[1] T. Scharnowski et al., “Fuzzware: Using Precise MMIO Modeling for Effective
    Firmware Fuzzing,” Boston, MA, Aug. 2022. [Online]. Available:
    https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski  
[2] B. Feng, A. Mera, and L. Lu, “P2IM: Scalable and hardware-independent
    firmware testing via automatic peripheral interface modeling,” in 29th
    USENIX Security Symposium, USENIX Security 2020, August 12-14, 2020, 2020,
    pp. 1237–1254. [Online]. Available:
    https://www.usenix.org/conference/usenixsecurity20/presentation/feng
