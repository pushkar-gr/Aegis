# Aegis Agent (Edge Data Plane)

The Aegis Agent is a Rust-based daemon designed to run on edge nodes (gateways). It utilizes `libbpf-rs` to load XDP programs directly into the kernel, enforcing a strictly "default-drop" network policy with minimal overhead.

## 🏗️ Architecture

The Agent operates as a gRPC server that listens for policy updates from the Controller and translates them into eBPF Map updates.

![Agent Packet Flow](./../docs/images/agent_architecture.png)
* **Control Path:** Receives `LoginEvent` RPC calls from the Controller and updates the `AllowedSessions` eBPF map.

[![](https://mermaid.ink/img/pako:eNqdVwtv4jgQ_itWVt1SKTzLM9etVOD2Wl2r5YB76GCFHGcCESHJ2sm2XLf__cZ2Xku3vXIgQTz2fP5mxjPjPBosdMCwjJOTRy_wYos8nsYb2MGpRU4dyrenJtGCPyj3qO2DwJlHPXeHqjiKeQK4yqZsu-ZhEjhS910T5FeqR9zbUb6fw0M8Cv2Qq2nXdeWc7wVQCOnA7rGulDM_ETHw4XatJlrd89Z5vzwRcge0UqfdhR49fXp6OjlZBmtOow25nS4Dgp-TEzKL90haD5lPhRiDS3y6B05cz_etd81Gs9Nkpoh5uAUrhUuH1XvPiTdWM3rIBA4VG8o53VukQzomk9ytdwDw08EW63AU7qIwgCBON2rTZrtfbARNG6D3_UYt3CiFRAcdQnI0XYKmeLZ73m0UeK7LWL9xDJ5jp0jnvXav7eZIzHX6DjsGibI4zP3Z6XZYIwcbNBh1B8eAbYEH4N8EGGaXMkhhMUq9gZ3D9ptO26X_AauBfxfAKxX5e3ZmWZbiqmfGw0Xlwr6c_XbrxYCji7p9eWHz-qVcLEwyA_7VY4BP0wQP0dlnVHfsDFcktj5tozBAGr4PfDVNgtjbAVn8EpLsOZ0mE58G8Fnryo_jcWCxFwZkPiykxVOOn7tidavO7aLwjRKUMF_GlZ_r-XyyQIPlP5mGCaLkJgcQ1zdxHJG75EHaWTq_BQgETmb9dwzvPMfx4Z7ynGIheTO70afpbCF_SnAvMpGfqyTeSHPkf0knN2kGQuBG9VEYbj2MwwbY9mjTrmngyMimdg0TgSVLCHIbrj32Ztskxeuca4qZE5VYQX3I-D6KX7U4PZAKKX1-BraeTkZk5Huy8GiSryGOsZ4pOPlgh5Q7ZcCjvTWmMc1cJZ_JFcP8EQd-mkIU6j1jalMB5E9Ujko2OOlEXXzxX-dwQCYnMsVaWWTj0pBjcrWWTqnM8TiE5ErsA3a2NP5PRiKbnSAL-ZcEHqNK57hclGFayRgCR3roDBU3Lcj9gFQRXpJEJ2Tl_yCAnohozDYZjOSEASzJc7RdJJhlTYGBh5u8BPpSaId5f1_Nqdii-YWEKMmbbZ8CjTK-8w2k45ynKm9fqY8tVhzL8taz7chdFRVyoSVVLoo6-maisy34EIeBpnoFa0_ksiJIM7wBMTxdclrOvhqvOxqtriY3GhEHaYaEhfm1HY1E5axGfT-8B2eFYdzg-FVPvJQGv6peKp0QJA_pqGT9X-PJCjloMjCcfJT0ciJ1sRd1V9TRfXUqjVshM03joEc_I4AXr58fcDKgvux_gfavKBoyqVbJ0pCNaIbh_5KAiJcGCi9Vk9LrZJkgF1I2HpaARzwUolrqrik6qWDTTQsf6qiM1_l0pnWz6kk-fMC9db7FHOiOVLRadeY5gI7GBZflBC1tjlsoq6VhHzE-ekI1VElUti8tUo1MGTlJbN9jqXWqETxbwcMYbQCntEivUe1CijLuB2JVvrWsmLkm7wtb3-s1arV0aMkW5aEfWFOyXPNTpZKklSXlWNSX9C6Vj7VOLYmwioM8t2p9eu6zyMqETxc6Mp9wIancYN_54fqcsk7mEtcsG0m1hlif7vGMGaR2qJ8O1GH6tjRme8Ewu3DptywFSm6RbwxesC7dSg9vYObhfcf87pZgFl3QVJ3CPKyd5rMypd5IDNNYc88xLPVKZeyA76gcGo-SzNJQL2JLw8JH-f61NJbBE-pENPg7DHeZGu6z3hiWS32BIx2GsUexIBRLMFWBj5BQbFgDhWBYj8aDYVXbzUbtvNHo9ZutjmnsUTKodVv4bfQ6vXa72-oPnkzjH7Vfs9YatPq9TgOv5o3GebPRNw1wPLxf3-m3SvVy-fQvSoGBXA?type=png)](https://mermaid.live/edit#pako:eNqdVwtv4jgQ_itWVt1SKTzLM9etVOD2Wl2r5YB76GCFHGcCESHJ2sm2XLf__cZ2Xku3vXIgQTz2fP5mxjPjPBosdMCwjJOTRy_wYos8nsYb2MGpRU4dyrenJtGCPyj3qO2DwJlHPXeHqjiKeQK4yqZsu-ZhEjhS910T5FeqR9zbUb6fw0M8Cv2Qq2nXdeWc7wVQCOnA7rGulDM_ETHw4XatJlrd89Z5vzwRcge0UqfdhR49fXp6OjlZBmtOow25nS4Dgp-TEzKL90haD5lPhRiDS3y6B05cz_etd81Gs9Nkpoh5uAUrhUuH1XvPiTdWM3rIBA4VG8o53VukQzomk9ytdwDw08EW63AU7qIwgCBON2rTZrtfbARNG6D3_UYt3CiFRAcdQnI0XYKmeLZ73m0UeK7LWL9xDJ5jp0jnvXav7eZIzHX6DjsGibI4zP3Z6XZYIwcbNBh1B8eAbYEH4N8EGGaXMkhhMUq9gZ3D9ptO26X_AauBfxfAKxX5e3ZmWZbiqmfGw0Xlwr6c_XbrxYCji7p9eWHz-qVcLEwyA_7VY4BP0wQP0dlnVHfsDFcktj5tozBAGr4PfDVNgtjbAVn8EpLsOZ0mE58G8Fnryo_jcWCxFwZkPiykxVOOn7tidavO7aLwjRKUMF_GlZ_r-XyyQIPlP5mGCaLkJgcQ1zdxHJG75EHaWTq_BQgETmb9dwzvPMfx4Z7ynGIheTO70afpbCF_SnAvMpGfqyTeSHPkf0knN2kGQuBG9VEYbj2MwwbY9mjTrmngyMimdg0TgSVLCHIbrj32Ztskxeuca4qZE5VYQX3I-D6KX7U4PZAKKX1-BraeTkZk5Huy8GiSryGOsZ4pOPlgh5Q7ZcCjvTWmMc1cJZ_JFcP8EQd-mkIU6j1jalMB5E9Ujko2OOlEXXzxX-dwQCYnMsVaWWTj0pBjcrWWTqnM8TiE5ErsA3a2NP5PRiKbnSAL-ZcEHqNK57hclGFayRgCR3roDBU3Lcj9gFQRXpJEJ2Tl_yCAnohozDYZjOSEASzJc7RdJJhlTYGBh5u8BPpSaId5f1_Nqdii-YWEKMmbbZ8CjTK-8w2k45ynKm9fqY8tVhzL8taz7chdFRVyoSVVLoo6-maisy34EIeBpnoFa0_ksiJIM7wBMTxdclrOvhqvOxqtriY3GhEHaYaEhfm1HY1E5axGfT-8B2eFYdzg-FVPvJQGv6peKp0QJA_pqGT9X-PJCjloMjCcfJT0ciJ1sRd1V9TRfXUqjVshM03joEc_I4AXr58fcDKgvux_gfavKBoyqVbJ0pCNaIbh_5KAiJcGCi9Vk9LrZJkgF1I2HpaARzwUolrqrik6qWDTTQsf6qiM1_l0pnWz6kk-fMC9db7FHOiOVLRadeY5gI7GBZflBC1tjlsoq6VhHzE-ekI1VElUti8tUo1MGTlJbN9jqXWqETxbwcMYbQCntEivUe1CijLuB2JVvrWsmLkm7wtb3-s1arV0aMkW5aEfWFOyXPNTpZKklSXlWNSX9C6Vj7VOLYmwioM8t2p9eu6zyMqETxc6Mp9wIancYN_54fqcsk7mEtcsG0m1hlif7vGMGaR2qJ8O1GH6tjRme8Ewu3DptywFSm6RbwxesC7dSg9vYObhfcf87pZgFl3QVJ3CPKyd5rMypd5IDNNYc88xLPVKZeyA76gcGo-SzNJQL2JLw8JH-f61NJbBE-pENPg7DHeZGu6z3hiWS32BIx2GsUexIBRLMFWBj5BQbFgDhWBYj8aDYVXbzUbtvNHo9ZutjmnsUTKodVv4bfQ6vXa72-oPnkzjH7Vfs9YatPq9TgOv5o3GebPRNw1wPLxf3-m3SvVy-fQvSoGBXA)

* **Data Path:** The XDP hook inspects every incoming packet. If the source/dest pair matches an entry in the map, it returns `XDP_PASS`. Otherwise, it returns `XDP_DROP`.

[![](https://mermaid.ink/img/pako:eNqVVW1v2zYQ_isE-6EuZqeyYlkWkaVI7A4L1qxCnQx70WBQ1MkWLIkCSSdxg_z38UWSHaMYEOiDyOd4z909x5dnzHgGmODRaJTUjNd5sSZJjZDaQAUEZVRs--kfVBQ0LUHaFcgab7U7QUrswGEpZdu14Ls6I-j9uzGY770zNaKoqNjfwZOa85ILsyDP89ZaFjX0MI3SkE1bCyt3UoG43q6NyZ-e--ezExMXGVjHYDKFkGqrrScv-SPbUKHQl2_OYan0bDBIcKzzBIWuhCgeQF6k4pLXCNTGS_CHD2g0ukQxFRL-SfBFemmH6FegOoq8-JhemvWfn5SgTKGbeIjuF_HHu3mc4H9dGOdgWOYbYNvrfUOlfLZcbuzwjupGogVIZYa6BUrwsgTxKcEvju2IQ3Oiv0Ciwbxfh-4EzfOCdVlLObCB_lzEq_hqueyCXJVaDeTq1kX-kPp3jgZLEA8Fg9e0t3QLv8Fey6EDS91uXbieE0O8FOwmRj-hhVTdP-ZC9WK0vpbnC-fbXXNLGyesHrRQl2Xa5KuKNqvSoisooeqJeueDsr-YneaE_awF2SMLfDJsr-WzeK_e1U5tuCi-Q-bKu28yqkBvDiVdYg5Ad0Wl-0KrPr0HWp6VVKqVBKjRz6jmj8dZ76zb66yPuPsO_Sgxo_19TU8yWwjeHPq5-PY17lK5LjnbHvfTkbotTgiR5t9idj9qrOTrgrXYUetPLG3DTtBefY3rWr82xzy2ihOHo8JPXGIXU5-egtcHPWyxPW4m3SnXSxaQI1sSyouyJO88zxvqjci3QMwt0o5Hj0WmNsRvnobMXiaPm0LBCY1NsqUZB9OAHZgij9E8egvZoYiOMQ3APzDSIJvS8O2MpvyWMQ3HbMx6RsgjGtG3MFrtW7I8CPNxeCxdEGX_S4aHeC2KDBNzyw9xBaKiZoqfTZgE27chwUQP7XOBk_pF-zS0_pvzqnPTb8J6g0lOS6ln7qAsCroW9LAEan3BzvVWUphElgGTZ_yEyWgy9s7OPS-cjf1giPcaic6mvv68MAgnk6k_i16G-LuNNz7zI38WBt7MCydTXSuGrFBc3LqXzj54L_8BWbNEmw?type=png)](https://mermaid.live/edit#pako:eNqVVW1v2zYQ_isE-6EuZqeyYlkWkaVI7A4L1qxCnQx70WBQ1MkWLIkCSSdxg_z38UWSHaMYEOiDyOd4z909x5dnzHgGmODRaJTUjNd5sSZJjZDaQAUEZVRs--kfVBQ0LUHaFcgab7U7QUrswGEpZdu14Ls6I-j9uzGY770zNaKoqNjfwZOa85ILsyDP89ZaFjX0MI3SkE1bCyt3UoG43q6NyZ-e--ezExMXGVjHYDKFkGqrrScv-SPbUKHQl2_OYan0bDBIcKzzBIWuhCgeQF6k4pLXCNTGS_CHD2g0ukQxFRL-SfBFemmH6FegOoq8-JhemvWfn5SgTKGbeIjuF_HHu3mc4H9dGOdgWOYbYNvrfUOlfLZcbuzwjupGogVIZYa6BUrwsgTxKcEvju2IQ3Oiv0Ciwbxfh-4EzfOCdVlLObCB_lzEq_hqueyCXJVaDeTq1kX-kPp3jgZLEA8Fg9e0t3QLv8Fey6EDS91uXbieE0O8FOwmRj-hhVTdP-ZC9WK0vpbnC-fbXXNLGyesHrRQl2Xa5KuKNqvSoisooeqJeueDsr-YneaE_awF2SMLfDJsr-WzeK_e1U5tuCi-Q-bKu28yqkBvDiVdYg5Ad0Wl-0KrPr0HWp6VVKqVBKjRz6jmj8dZ76zb66yPuPsO_Sgxo_19TU8yWwjeHPq5-PY17lK5LjnbHvfTkbotTgiR5t9idj9qrOTrgrXYUetPLG3DTtBefY3rWr82xzy2ihOHo8JPXGIXU5-egtcHPWyxPW4m3SnXSxaQI1sSyouyJO88zxvqjci3QMwt0o5Hj0WmNsRvnobMXiaPm0LBCY1NsqUZB9OAHZgij9E8egvZoYiOMQ3APzDSIJvS8O2MpvyWMQ3HbMx6RsgjGtG3MFrtW7I8CPNxeCxdEGX_S4aHeC2KDBNzyw9xBaKiZoqfTZgE27chwUQP7XOBk_pF-zS0_pvzqnPTb8J6g0lOS6ln7qAsCroW9LAEan3BzvVWUphElgGTZ_yEyWgy9s7OPS-cjf1giPcaic6mvv68MAgnk6k_i16G-LuNNz7zI38WBt7MCydTXSuGrFBc3LqXzj54L_8BWbNEmw)

## 📋 Prerequisites

To build the Agent from source, you need a Linux environment with the BPF toolchain installed.

**System Dependencies (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev pkg-config \
    linux-tools-generic build-essential protobuf-compiler

```

**Rust Toolchain:**
Ensure you have the latest stable Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh

```

**Generate Kernel Type Definitions (vmlinux.h):**
The eBPF program relies on `vmlinux.h` to access kernel structures (CO-RE). You must generate this header for your specific running kernel before building.

1.  **Install bpftool** (if not already installed):
    ```bash
    # Debian/Ubuntu
    sudo apt install linux-tools-common linux-tools-generic linux-tools-$(uname -r)
    
    # Fedora/RHEL
    sudo dnf install bpftool
    ```

2.  **Generate the header**:
    Run this command from the `agent/` directory:
    ```bash
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
    ```

> **Note:** If you are cross-compiling or building for a different kernel version, you may need to point `bpftool` to that specific kernel's BTF file.

## 🛠️ Build

The build process compiles both the Rust userspace daemon and the C eBPF kernel code.

```bash
cd agent
# The build.rs script will automatically compile the BPF C code
cargo build --release

```

## 🏃 Usage

The Agent requires `CAP_BPF` (or `root`) privileges to load XDP programs into the kernel network interface.

```bash
sudo ./target/release/aegis-agent [OPTIONS]

```

### Configuration Flags

Configuration is handled via command-line arguments.

| Flag | Long Flag | Default | Description |
| --- | --- | --- | --- |
| `-i` | `--iface` | `eth0` | The network interface to attach the XDP firewall to. |
| `-c` | `--ip` | `172.21.0.5` | The IPv4 address of the Aegis Controller. |
| `-p` | `--port` | `443` | The gRPC port of the Controller. |
| `-g` | `--grpc-port` | `50001` | The port this Agent listens on for instructions. |
| `-r` | `--rule-timeout` | `60s` | Time (in ns) before a rule is auto-revoked. |
| N/A | `--cleanup-interval` | `30s` | How often the reaper checks for expired rules. |

**Example:**

```bash
sudo ./target/release/aegis-agent \
  --iface eth1 \
  --ip 10.0.0.50 \
  --grpc-port 50051

```
