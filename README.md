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

常规运行每天上海时间 `05:30` 触发，恢复时补跑最近一次错过的触发。临时网络错误在现役批次可确认、没有待恢复记录且 PRM 空闲时重试一次。`PUBLISH_SCHEDULE_ENABLED=0` 可暂停自动触发并保留手动命令。日志和 `state/last-check.json` 提供结果，校验拒绝的候选不会接管下载。首次需要 `linux/amd64` 的 Mihomo 时，发布器从官方发行版下载并核验已固定的摘要，然后在 NAS 发布状态中缓存。

经过人工审阅的规则变更使用 `stage --reviewed /data/config/expected.yaml`，再按报告中的批次运行 `promote <batch>`。私有参考包含当时的 `base` 批次与完整预期 `bundle`，后者包含 `rule-providers`、`rules`。从已知批次构建时固定其规则源版本并沿用四库。首次发布的 `base` 为空字符串，参考须额外提供 `sources`，按源标识映射 `[仓库, 完整提交]`。预期规则应独立核对并保存在私有配置目录。

路由器应将公开文件请求转发到源站的 `/active/`，其中包括 `GeoSite.dat`、`GeoIP.dat`、`Country.mmdb`、`ASN.mmdb` 和 `rules/mihomo/<id>.yaml`。源站的 NAS 映射只允许 `ORIGIN_ALLOWED_IP` 访问，内部校验端口留在 Compose 网络。使用生产公网 URL 进行逐文件回读时，设置 `RULES_ORIGIN_URL` 为该入口的基地址。

## 验证

```sh
docker build -t home-rules:test .
docker run --rm home-rules:test python3 -m unittest -v
```

GitHub Actions 构建并测试源码，为 `v*` 标签发布对应的 GHCR 镜像。MIT 许可证覆盖本仓库的自有代码。PRM 镜像、Mihomo、外部规则和 Geo 数据均来自各自上游。
