# Home Rules

通过一套 Docker Compose 运行 Proxy Rule Manager（PRM）、规则发布器和下载源站。PRM 聚合规则，发布器校验候选并切换当前批次，静态源站提供当前批次的公开文件。

## 部署

1. 将 `compose.env.example` 复制为权限为 `0600` 的 `.env`，填入自有镜像版本或摘要、部署目录、发布进程的 UID/GID、PRM 凭据和静态源站地址。生产下载入口在反代端使用 HTTPS。
2. 在配置目录提供 `sources.yaml`、`household-rules.yaml` 和 `probes.yaml`。依次为发布策略、家庭增补规则、实际路由核验用例。发布策略的顶层键为 `sources`、`providers`、`early_rules`、`rules`，可选 `automatic_additions`。`probes.yaml` 包含 `baseline` 和 `converged`，以域名或地址映射到 `[Mihomo 匹配说明, 策略组]`。
3. 准备独立的 PRM 数据和发布状态目录，让发布进程可读写状态、只读配置。由现有部署迁移时保留 `state/current` 和 `.publish.lock` 的消费者路径。静态源站用同一 UID/GID 只读挂载状态。
4. 运行以下命令。新 PRM 数据可用 `seed` 初始化，已有数据继续按原配置或通过 `adopt-config` 核对后登记。

```sh
docker compose pull
docker compose up -d
docker compose logs publisher
docker compose exec publisher python3 -m prm_release publish
```

常规运行在上海时间 `05:30` 到 `23:30` 之间每三小时检查一次，恢复时补最近的时段。同一现役批次与已处理输入相同时跳过重复编译，每天至少做一次完整公网回读。临时网络错误在现役可确认并且 PRM 空闲时重试一次。`PUBLISH_SCHEDULE_ENABLED=0` 可关闭定时检查。手动 `publish` 会立即重新检查。`state/last-scheduled.json` 保留最近定时结果，`state/last-check.json` 记录最近操作。首次需要 `linux/amd64` 的 Mihomo 时，发布器从官方发行版下载并核验已固定的摘要，然后在 NAS 发布状态中缓存。

日常发布先尝试全部输入。只有能定位到已知集合或旧版可验证的 Geo 输入时，才在重新校验后发布包含这些旧产物的统一批次。私有清单 `rule_inputs` 记录每个实际发布集合的来源，报告同时保留待审差异和保留的输入。发布策略的 `automatic_updates` 可声明 `proxy` 集合、`proxy_removals`、`services` 专用域根、`domestic_ip` 和 `deferred_direct` 区间。默认只接受可证明等价的变化。`domestic_ip` 仅允许经上一有效 `Country.mmdb` 整段核对为 `CN` 且由兜底进入直连的新增区间。

经过人工审阅的规则变更使用 `stage --reviewed /data/config/expected.yaml`，再按报告中的批次运行 `promote <batch>`。私有参考包含当时的 `base` 批次与完整预期 `bundle`，后者包含 `rule-providers`、`rules`。从已知批次构建时固定其实际规则源版本并沿用四库。要采用已审阅的上游提交，另提供 `sources` 和 `advance`，分别按源标识明确 `[仓库, 完整提交]` 并按名称列出采用新版的集合。未点名集合仍用现役的有效来源。首次发布的 `base` 为空字符串，参考须提供 `sources`。预期规则应独立核对并保存在私有配置目录。

路由器应将公开文件请求转发到源站的 `/active/`，其中包括 `GeoSite.dat`、`GeoIP.dat`、`Country.mmdb`、`ASN.mmdb` 和 `rules/mihomo/<id>.yaml`。源站的 NAS 映射只允许 `ORIGIN_ALLOWED_IP` 访问，内部校验端口留在 Compose 网络。使用生产公网 URL 进行逐文件回读时，设置 `RULES_ORIGIN_URL` 为该入口的基地址。

## 验证

```sh
docker build -t home-rules:test .
docker run --rm home-rules:test python3 -m unittest -v
```

GitHub Actions 构建并测试源码，为 `v*` 标签发布对应的 GHCR 镜像。MIT 许可证覆盖本仓库的自有代码。PRM 镜像、Mihomo、外部规则和 Geo 数据均来自各自上游。
