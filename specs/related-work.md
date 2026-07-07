# Kill-check: verifiable ANN landscape (2024–2026)

目标顶点：{图索引 × 每查询常开验证 × VO 亚线性于 d × 动态更新}。
Kill 判据：若任何 2025–26 工作同时占住前三个坐标 → 启动 Plan B（filtered-ANN 完整性模块）。

## 判定结论（2026-07 扫描）

**Niche 开放，不启动 Plan B。** 截至 2026-07，无任何已发表 / 预印本工作同时占住
{图索引 × 每查询常开 × 证明亚线性于 d} 三坐标：

- 占「图 × 常开」的（ANNProof、VIS/guided tuples）证明 / VO 均 **∝ d**（proof 携带原始向量），
  占不到第三坐标，且均为 2024 年工作；
- 占「证明亚线性于 d」的 **V3DB**（2026）是 **IVF-PQ（非图）+ 按需 ZK 审计（非常开）**；
- 2026 并发的 **VeriANN** 是 **LSH（非图）+ 两服务器 PIR/GC**，隐私优先，非便宜常开。

TraceANN 的 Tier-1 已唯一占住「图 × 常开 × 形式化 trace-consistency soundness +
跨平台整数精确 determinism」；第三坐标「VO 亚线性于 d」是 Tier-2（聚合 IPA）目标——
V3DB 证明 d-简洁证明可达（靠 ZK on IVF-PQ），但在**图索引 + 常开**下把 VO 压到亚线性于 d
尚无人做到。

## 定位表

| 工作 | 年份 / venue | 索引 | 验证模式 | 证明/VO ∝ d? | 信任模型 | 常开? | 开源 |
|---|---|---|---|---|---|---|---|
| ANNProof | 2024, FGCS 156:206–220 | HNSW 图 | Merkle ADS，逐查询 VO | **是**（∝d） | 单服务器 + 链上 ADS | 是 | 未见公开仓库 |
| VIS / guided tuples | 2024, ADMA (LNCS 15389:3–17) | 图 | guided-tuple VIS，逐查询 VO | **是**（∝d，已优化） | 单服务器 | 是 | 未见公开仓库 |
| V3DB | 2026, arXiv 2603.03065 | **IVF-PQ**（非图） | 按需 ZK-SNARK (Plonky2) | 否（ZK 简洁） | 单服务器 | **否**（仅受挑战时） | 是 (zk-IVF-PQ) |
| VeriANN | 2026, IACR ePrint 2026/923 | **LSH**（非图） | 两服务器 PIR + 认证 GC | N/A（GC；客户端单次 hash 校验） | **两服务器非共谋** | 是 | 待查 |
| **TraceANN**（本工作） | — | **HNSW 图** | **常开 trace-consistency Merkle VO** | Tier-1 是 → **Tier-2 否**（IPA） | 单服务器 | **是** | 是 (traceann) |

坐标占用：图 ✓ = {ANNProof, VIS}；常开 ✓ = {ANNProof, VIS, VeriANN}；证明亚线性于 d ✓ = {V3DB}。
三集合两两有交、但**三者交集为空** → 目标顶点无人占据。

## 验证-ANN 谱系（供 §2 叙事）

Papadopoulos et al. 2011（authenticated multistep NN, IEEE TKDE 23(5):641–654）
→ Jing et al. 2013（road-network kNN authentication, IEEE TKDE）
→ Cui et al. 2023（multi-user, secure, verifiable kNN, IEEE TKDE；V3DB 与 VIS 均引）
→ ANNProof 2024（图 + 链上 Merkle ADS）/ VIS 2024（图 + guided tuples）
→ V3DB 2026（IVF-PQ + ZK 按需）/ VeriANN 2026（LSH + 两服务器隐私 + 完整性）。

正交但相邻的**隐私-ANN**簇（非完整性，勿混入 kill）：Pacmann、PANTHER (CCS'25)、
Compass、Tiptoe、Wally——均只做 query privacy / confidentiality，无结果正确性验证。

TraceANN 接在这条线的**图 + 常开 + 便宜 VO + 形式化 soundness + 跨平台 determinism**分支上，
Tier-2 目标是把「d-简洁证明」带到图 + 常开一侧（V3DB 只在 IVF-PQ + 按需 + ZK 代价下拿到）。

## 与最接近工作的三重 delta（写 §1/§2 用）

1. **图索引上的常开 + 便宜 VO**：prove 325µs、verify 2.7ms 的 Merkle VO，不付 ZK/PIR/GC 代价；
   ANNProof/VIS 虽也常开但 VO∝d，V3DB/VeriANN 付重加密换取 d-简洁 / 隐私。
2. **形式化 trace-consistency soundness**：Lemma 2b（replay-coincidence）+ 显式 reduction B
   把「验证通过 ⇒ 结果 = 承诺索引上确定性执行」证到碰撞归约；ANNProof/VIS 只有经验 VO，
   V3DB 有 ZK soundness 但针对 IVF-PQ + 按需模型。
3. **跨平台 bit-exact determinism**：整数精确距离、hash 派生层、x86-64 与 aarch64 golden
   digest 逐位一致——把 reference execution 的可复现性当一等属性；既往图-验证工作均未处理。

## 复扫参数（下次刷新用）

检索关键词：verifiable approximate nearest neighbor / authenticated vector database /
integrity HNSW / verifiable similarity search / verifiable retrieval / encrypted ANN verifiable。
渠道：Google Scholar (ANNProof / V3DB / VeriANN 的 Cited-by)、eprint.iacr.org、dblp.org、
arXiv cs.CR + cs.DB。上次扫描：2026-07-07。
