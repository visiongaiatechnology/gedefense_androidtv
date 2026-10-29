<p align="center">
  <img src="docs/assets/sir_quacksec.png" alt="Sir Quacksec — GeDefense TV" width="200">
</p>

<h1 align="center">GeDefense TV</h1>

<p align="center"><b>Android TV OS / Google TV 向けのオンデバイス・セキュリティコンソール。</b><br>
ローカル・ループバック VPN フィルタリング、地理位置情報付きトラフィックマップ、XDR-Light、そして正直な状態モデル。<br>
外部 VPN サーバーなし。クラウドなし。テレメトリなし。</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk"><img src="https://img.shields.io/badge/release-0.2.0--alpha1-E8C46A?style=flat-square" alt="リリース 0.2.0-alpha1"></a>
  <img src="https://img.shields.io/badge/status-early%20alpha-E86A5A?style=flat-square" alt="早期 Alpha">
  <img src="https://img.shields.io/badge/platform-Android_TV%20%7C%20Google_TV-5FBFA8?style=flat-square" alt="Android TV / Google TV">
  <img src="https://img.shields.io/badge/Kotlin-1.9.24-7F52FF?style=flat-square&logo=kotlin&logoColor=white" alt="Kotlin 1.9.24">
  <img src="https://img.shields.io/badge/minSdk-26-3DDC84?style=flat-square&logo=android&logoColor=white" alt="minSdk 26">
  <img src="https://img.shields.io/badge/license-VGT%20proprietary-B08D57?style=flat-square" alt="VGT 専有ライセンス">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Русский](README.ru.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · **日本語**

---

> ## ⚠️ 早期 ALPHA（early alpha）— すべてのユーザーがアルファテスターです
>
> GeDefense TV **0.2.0-alpha1** は早期アルファ版です。完成したコンシューマー製品でも、監査済みの
> セキュリティ製品でもありません。公開 APK は**テスト署名鍵**で署名されています。動作、UI、フィルタリング
> ポリシーはアルファ版ごとに変わります。依拠する前に[適用範囲と制限](#適用範囲と制限)と
> [リリースノート](RELEASE-NOTES.md)を読み、すべての結果を保証ではなく手がかりとして扱ってください。

## ダウンロード

[![最新のアルファ APK をダウンロード](https://img.shields.io/badge/Download-latest%20APK-E8C46A?style=for-the-badge&logo=android&logoColor=black)](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk)

常に[最新リリースページ](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk)を使用してください。
正確な APK アセット、チェックサム、ビルドノートはそこにあります。アルファ APK はテスト署名されているため、
サイドロード時に Android が警告を表示することがあります。インストール前に SHA-256 を
[SHA256SUMS.txt](SHA256SUMS.txt) またはリリースに添付されたチェックサムと照合してください。

## スクリーンショット

実行中の Android TV エミュレータービルド（1920×1080、Android 16 Google TV / API 36）から取得した
英語 UI の実際のレンダリングです。

| ホーム — セキュリティ状況 | 保護 — ローカル・ループバック VPN |
| --- | --- |
| ![ホーム画面](docs/screenshots/home.png) | ![保護ダッシュボード](docs/screenshots/protection.png) |

| ネットワーク — トラフィックマップと接続先 | 取り消し可能な一時封じ込めポップアップ（Kinetic-Lite） |
| --- | --- |
| ![ネットワークとトラフィックマップ](docs/screenshots/network.png) | ![一時封じ込めポップアップ](docs/screenshots/containment.png) |

| Sir Quacksec による初回セットアップ | XDR-Light — 相関インシデント | 脅威インテリジェンス同期オーバーレイ |
| --- | --- | --- |
| ![初回セットアップ ステップ 1](docs/screenshots/onboarding.png) | ![XDR-Light インシデント](docs/screenshots/xdr.png) | ![脅威インテリジェンス同期](docs/screenshots/ti-sync.png) |

### 6 つの UI 言語

UI はテレビのシステム言語に従います。英語が既定で、ドイツ語・フランス語・ロシア語・簡体字中国語・
日本語には完全なリソースセットが用意されています。

| English（既定） | Deutsch | Français |
| --- | --- | --- |
| ![英語ホーム](docs/screenshots/home.png) | ![ドイツ語ホーム](docs/screenshots/languages/home-de.png) | ![フランス語ホーム](docs/screenshots/languages/home-fr.png) |

| Русский | 简体中文 | 日本語 |
| --- | --- | --- |
| ![ロシア語ホーム](docs/screenshots/languages/home-ru.png) | ![中国語ホーム](docs/screenshots/languages/home-zh-CN.png) | ![日本語ホーム](docs/screenshots/languages/home-ja.png) |

## GeDefense TV とは

GeDefense TV は、Android TV OS と Google TV 向けの、D-pad（リモコン）操作を最優先にしたセキュリティ
アプリです。ローカルなフィルタリング層とローカルな可観測コンソールを組み合わせ、テレビがネットワーク上で
何をしているか、何がブロックされたか、どのアプリがどの国と通信しているか、そしてどの検出事項が実際に
このデバイス上で検証可能かを表示します。

基本原則は「**このデバイスで観測できることだけを報告する**」ことです。権限の欠如、未対応 API、部分的な
可視性は、あくまで部分的可視性として表示され、テレビが「クリーン」である証拠として扱われることはありません。
保護状態は、トンネルが実際に動作している場合にのみ宣言されます。

本アプリは**独立したテレビアプリ**です。ルーター、ファイアウォールゲートウェイ、ネットワークセンサーでは
なく、ルーターファームウェアとも統合しません。

### なぜローカルのみのループバック VPN なのか

GeDefense TV はデバイス上で直接フィルタリングします。アプリはローカル TUN インターフェースを作成し、
自身のトラフィックをそこに通し、同梱された監査済みデータプレーン・ヘルパーが DNS と接続メタデータを
評価します。フィルタリングされたトラフィックはその後、デバイスから宛先へ直接送出されます。

この設計には意図的な結果があります。

- **外部サーバーなし、アカウントなし、サブスクリプションなし。** トラフィックは VGT サーバーや第三者の
  VPN エンドポイントを経由しないため、信頼すべき中間点が存在しません。
- **ペイロード検査なし。** 評価するのは DNS と接続メタデータのみです。TLS/QUIC の内容は暗号化された
  まま手を加えません。MITM プロキシではなく、HTTPS の内部を見ることはできません。
- **ローカルな証拠。** 検出事項、カウンター、証拠はテレビ上に留まります。何もアップロードされません。
- **正直な失敗。** 同意がない、ヘルパーが失敗する、ポリシーを評価できない場合は、フィルタリングなしで
  静かに通過させるのではなく、劣化/失敗状態を報告します。

## 機能

### ローカル保護（ループバック VPN）

- デバイス上の TUN サービス（`VpnService`、フォアグラウンドサービス、Always-On 対応）と、
  `arm64-v8a` / `x86_64` 用の同梱ネイティブヘルパー。
- Android の一度限りの VPN 同意による開始/停止。アプリ起動後の自動開始はオプション。
- フィルタープロファイル：**Off**、**Conservative**、**Balanced**、**Strict**。各プロファイルは既知の
  テレメトリ、ACR、広告、トラッカー、C2 宛先の扱いの強さを変更します。
- 明示的な状態モデル：Off、Preparing、Active、Limited、Failed、Not supported。ローカルトンネルが実際に
  動作している間だけ「Active」を表示します。
- ライブカウンター：ブロックされたフロー、観測アプリ、アクティブフロー、開始以降の転送量。

### フィルタリング：DNS、トラッカー、ACR、広告、C2

- 同梱の脅威インデックス、精選されたトラッカー/テレメトリカタログ、選択したプライバシープロファイルに
  基づき、DNS クエリと接続先をローカルで評価します。
- アクションは説明可能：許可、注釈、相関、ブロック。理由はローカルポリシーに由来し、リモートの判定では
  ありません。
- 公開 IOC リストから供給される有界の脅威インテリジェンスキャッシュ。古いフィードは非表示にせず、
  古いと明示します。
- 正直な制限：アプリが DNS-over-TLS/HTTPS を使用する場合、ドメイン名は見えません。推測せずにその旨を表示します。

### ローカル地理属性付きトラフィックマップ

- 観測トラフィックのアプリ別・国別・ドメイン別集計：バイト数、アクティブフロー、ブロックされたフロー、
  相関したフロー。
- 国マーカーと、テレビのリージョン/ネットワークから導出した起点マーカーを表示する世界地図。
  **GPS なし、位置情報権限なし。**
- IP→国の属性は、SHA-256 チェックサム付きで一度だけダウンロードするオフラインデータセットを使用します。
  国別属性は推定であり、CDN、エニーキャスト、共有ホスティングでは誤って割り当てられることがあります。
- 有界でプライバシーに配慮したデータ：ペイロード、画面内容、音声/映像、パケット単位のログは保持しません。

### XDR-Light

ローカルで観測可能な事象を、説明可能なインシデントに相関させます：アプリごとの繰り返しブロック、
ブロックされたテレメトリ/ACR トラフィック、初観測のアプリトラフィック、C2 フィード一致、高リスク国
コリドー（情報提供のみ）。各インシデントにはルール、信頼度、可視性、推奨事項が付きます。重複排除され、
有界であり、特権 EDR では**ありません**：システム全体のフロー、プロセス監視、ファームウェア整合性の主張は
行いません。

### V2.1 Outbound Kinetic-Lite

観測された外向きトラフィックに対する、決定的で有界なスライディングウィンドウ・ヒューリスティック：
DNS バースト、宛先ファンアウト、ビーコンパターン、ボリュームスパイク、繰り返しブロック、トラッカー
カテゴリ、C2 一致、高リスクコリドー。各異常は名前付きシグナルを持つスコアであり、「マルウェア」判定では
ありません。

**既定は監視のみ。** 一時的な封じ込めは明示的なオプトインで、「Strict」プロファイルでのみ利用できます。
有効にすると宛先プレフィックスのみが封じ込められ（アプリは封じ込めません）、厳格なガードレールが適用
されます：少なくとも 2 つの独立したシグナル、最低スコア、既知の宛先国、短い TTL（1〜30 分、既定 10 分）、
最大 4 件のアクティブ封じ込め、プラットフォーム・Google・CDN 範囲の許可リスト。すべての封じ込めは取り
消し可能で、テレビにポップアップが表示され、**元に戻す**を押すことができ、TTL の満了で自動的に解除されます。

### Sir Quacksec による初回セットアップ

6 ステップの D-pad 専用ウィザード：ようこそ、ローカル保護の仕組み、VPN 同意、脅威インテリジェンス同期
（スキップ可能）、初回チェック、完全保護を有効化するサマリー。偽装は一切ありません。同意が拒否されたり
ステップが失敗した場合は、その旨を伝えます。

### 脅威インテリジェンス同期オーバーレイ

公開 IOC フィードの更新中に、D-pad セーフなオーバーレイで同期の進捗を表示します。古い、または失敗した
同期は正直に報告され、後で再試行できます。

### 証拠、レポート、エクスポート

- HMAC 検証済みハッシュチェーンと暗号化ペイロードを備えたローカル証拠レジャー。鍵を失った場合は、
  静かに新しいチェーンを開始せず fail-closed で動作します。
- ローカルのテキストおよび JSON セキュリティレポート。
- システムのファイルピッカー（SAF）によるエクスポート。ドキュメントピッカーのないテレビイメージでは、
  権限不要の `Downloads/GeDefenseTV` フォールバックを使用し、ファイルの保存先をユーザーに伝えます。

### 6 言語の完全ローカライズ

英語（既定）、ドイツ語、フランス語、ロシア語、簡体字中国語、日本語。すべての UI 文字列に完全なリソース
セットがあり、リポジトリの翻訳チェッカーで検証されます。

### デバイス監査と検出事項

フィルタリングに加えて、GeDefense TV は製品当初からの読み取り専用の監査サーフェスを維持します：

- **デバイス状態：** Android のバージョン/API レベル、ビルドフィンガープリント、ABI、セキュリティ
  パッチの経過分類 — あくまでメタデータであり、脆弱性がないことの保証ではありません。
- **可視アプリ：** バージョン、インストーラー、署名ダイジェスト、ベースラインに対する「新規/変更」
  状態。Android のパッケージ可視性の制限は隠さず表示します。
- **ハードニング検査：** ADB/デバッグ、開発者オプション、test-keys/userdebug ビルド、デバイス管理者、
  アクセシビリティサービス、ストア外インストーラー — 三値判定で、読み取れない値は読み取れないまま
  保持され、「安全」と見なされることはありません。
- **検出事項と脅威インテリジェンス：** 重大度、信頼度、可視性を伴う説明可能な検出事項に加え、
  ローカルフィードの鮮度とインジケーター一致。

### 正直な状態モデル

状態モデルそのものが製品です。機能と可視性は第一級のデータです。緑の「安全」バッジの代わりに、十分な
カバレッジがある場合にのみセキュリティスコアを表示し、部分的可視性を明示し、何が観測できなかったかを
明確に述べます。

## 仕組み

```text
Android TV / Google TV（root 化なし）
┌──────────────────────────────────────────────────────────────────────────┐
│ :app  （通常のアプリサンドボックス、AndroidX なし、第三者ランタイムなし）  │
│   UI（Views、D-pad）  Protection  Network  XDR  Onboarding  Settings      │
│   コントラクト / サービス                                                  │
│        │                                                                  │
│   TvVpnService（フォアグラウンドサービス、ローカル TUN）                   │
│        │  有界の制御 + テレメトリ                                         │
│        ▼                                                                  │
│   GaiaNet ヘルパー（同梱ネイティブ .so、子プロセス、root なし）            │
│        DNS/フローポリシー  →  宛先へ直接送信                              │
└──────────────────────────────────────────────────────────────────────────┘
     :tv-core — 純粋な JVM ドメイン：スキャン、スコアリング、トラフィック、XDR、
                 異常、封じ込めポリシー、地理ヘルパー、レポート、イベント
     :core    — 同梱の GeDefense Mobile コア（バイト単位で同一）
```

## 適用範囲と制限

GeDefense TV は意図的に次では**ありません**：

- 外部 VPN や地域制限解除サービス — サーバーはなく、デバイス外へトンネルされるものはありません。
- アンチウイルスやマルウェア駆除ツール — ネットワーク動作を観測して報告しますが、アプリを駆除しません。
- 特権 EDR — カーネルアクセス、root、システム全体のプロセス/フロー監視はありません。
- ルーター/ゲートウェイ/ファイアウォールの代替 — テレビ上でのみ動作します。
- 完全なアプリ一覧 — Android のパッケージ可視性が、アプリから見える範囲を制限します。
- 保護の保証 — フィルタリングは実際にローカルデータパスを通るトラフィックと、既知のポリシーにのみ及びます。

その他の既知の制限：

- **アルファ品質：** 実機テレビ（OEM デバイス）では未検証です。現在の証拠基盤はエミュレーターの動作です。
- **DNS 可視性：** DoT/DoH トラフィックはドメイン名をローカル観測から隠します。
- **地理属性は近似値：** CDN、エニーキャスト、共有ホスティングは誤った国に割り当てられることがあります。
- **封じ込めは設計上一時的：** 短い TTL、最大 4 件のアクティブブロック、簡単に取り消し可能。恒久的な
  ファイアウォールルールではありません。
- **テスト署名されたアルファ APK：** 本番署名ビルドではありません。サイドロードには提供元不明アプリの
  許可が必要です。

## セキュリティとプライバシー

- **テレメトリ、解析、広告、クラッシュ SDK なし。** 第三者のランタイム SDK を一切含みません。
- **コンテンツ収集なし：** 画面、音声、映像、ペイロードを収集せず、TLS 傍受も行いません。
- **既定はローカル処理：** トラフィックメタデータ、検出事項、証拠はデバイス上に留まります。
- **最小権限：** `INTERNET`、`ACCESS_NETWORK_STATE`、`FOREGROUND_SERVICE`、
  `FOREGROUND_SERVICE_SPECIAL_USE`、`POST_NOTIFICATIONS`、およびサービス権限 `BIND_VPN_SERVICE`。
  位置情報、アクセシビリティ、オーバーレイ、カメラ、マイク、`QUERY_ALL_PACKAGES` は使用しません。
- **デバイスから出るのは公開データのみ：** 脅威インテリジェンスフィードと IP→国データセットを HTTPS で
  取得します。デバイスデータはアップロードされません。
- **セキュリティ報告：** [SECURITY.md](SECURITY.md) を参照してください。公開 issue に悪用可能な詳細を
  投稿しないでください。

データインベントリ全体：[PRIVACY.md](PRIVACY.md) · [DATA-SAFETY.md](DATA-SAFETY.md)。
セキュリティ設計と脅威モデル：[SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md)。

## 要件

| コンポーネント | 要件 |
| --- | --- |
| デバイス | Android TV OS / Google TV、`minSdk 26`（Android 8.0）以上、`arm64-v8a` または `x86_64` |
| テレビ UI | Leanback 対応ランチャー、D-pad リモコン（タッチ不要） |
| ビルド | JDK 17、Android SDK プラットフォーム 36、Build-Tools 36.0.0、Gradle 8.7（wrapper 同梱） |
| ランタイム依存 | なし — AndroidX なし、第三者ライブラリなし |

## インストール（サイドロード）

1. テレビで、APK のインストールに使用するアプリ（サイドロード/ファイルマネージャー、または ADB）に対して
   提供元不明アプリのインストールを許可します。
2. [最新リリース](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk)から APK をインストールします。
3. **GeDefense TV** を起動し、初回セットアップに従い、Android の一度限りの VPN 同意ダイアログを承認します。
4. 任意で ADB を使用：

```bash
adb connect <tv-ip>:5555
adb install -r VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-debugsigned.apk
adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity
```

アルファ APK は**テスト署名**されています。本番署名鍵はこのアルファには含まれません。

## ソースからビルド

```bash
git clone https://github.com/visiongaiatechnology/gedefense_androidtv.git
cd gedefense_androidtv

export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk

./gradlew :app:assembleDebug           # デバッグ APK
./gradlew :app:assembleRelease         # R8 で縮小したリリース APK
```

リリース署名は環境変数 `GEDEFENSE_RELEASE_STORE_FILE`、`GEDEFENSE_RELEASE_STORE_PASSWORD`、
`GEDEFENSE_RELEASE_KEY_ALIAS`、`GEDEFENSE_RELEASE_KEY_PASSWORD` を読み取ります。未設定の場合、ビルドは
デバッグ署名にフォールバックします。アルファテストには適していますが、配布には適していません。
詳細：[BUILD-RUNBOOK.md](BUILD-RUNBOOK.md)。

## テスト

```bash
./gradlew :tv-core:tvCoreCheck     # コアドメインのハーネス
./gradlew :tv-core:tvV2Check       # トラフィック / プライバシー / XDR ハーネス
./gradlew :tv-core:tvKineticCheck  # V2.1 異常検知と封じ込めのハーネス
./gradlew :app:lintDebug           # Android lint
```

同梱コアのハーネス（`:core:coreCheck`）は Linux/macOS の JVM が必要です。堅牢なファイル処理がディレクトリの
`fsync` を使用しており、Windows ではサポートされていません。AVD の作成とスクリーンショット取得を含む
Android TV エミュレーターガイドは [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md) にあります。
受け入れマトリクスは [TEST-PLAN.md](TEST-PLAN.md) です。

## プロジェクト構成

```text
.
├── app/                    Android TV アプリモジュール（Views、AndroidX なし）
│   └── src/main/            java/ · res/（6 言語）· assets/ · jniLibs/ · AndroidManifest.xml
├── core/                   同梱の GeDefense Mobile コア（バイト単位で同一、純粋な JVM）
├── tv-core/                純粋な JVM ドメイン：スキャン、スコアリング、トラフィック、XDR、異常、レポート
├── docs/                   アーキテクチャ、トラフィックマップ、オンボーディング、デザイン DNA、
│                           エミュレーターガイド、screenshots/ と assets/
├── tools/                  ビルド/テスト/エミュレーター/リモート/検証スクリプト
├── gradle/ + gradlew*      Gradle 8.7 wrapper（ディストリビューション SHA-256 を固定）
├── build.gradle.kts        AGP 8.5.2 · Kotlin 1.9.24 · Java 17
└── settings.gradle.kts     モジュール :core, :tv-core, :app
```

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | モジュールグラフ、データフロー、コレクター、証拠、パフォーマンス予算 |
| [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md) | ループバック VPN、テレメトリ、トラフィック集計、ネイティブヘルパーのサプライチェーン |
| [docs/TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md) | トラフィックマップのデータソース、制限、色、プライバシー |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | 初回起動ウィザード、同意と権限の説明 |
| [docs/DESIGN-DNA.md](docs/DESIGN-DNA.md) | テレビ向けデザインシステム、フォーカス/インタラクション規則、禁止パターン |
| [SECURITY.md](SECURITY.md) | セキュリティ設計、鍵の保管、権限、報告ポリシー |
| [THREAT-MODEL.md](THREAT-MODEL.md) | 資産、信頼境界、STRIDE 分析、テレビ固有のリスク |
| [PRIVACY.md](PRIVACY.md) | データインベントリ、保持、エクスポート、権限の根拠 |
| [TEST-PLAN.md](TEST-PLAN.md) | 受け入れマトリクスと証拠要件 |
| [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md) | ビルド、署名、ログ、トラブルシューティング |
| [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md) | Android TV エミュレーターのステップバイステップガイド |
| [docs/SOURCES.md](docs/SOURCES.md) | 出典と参照 |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | このアルファの変更点と検証状況 |

## ライセンスと第三者通知

GeDefense TV は **VisionGaiaTechnology（VGT）の専有ソフトウェア**です。このリポジトリは透明性、レビュー、
アルファテストのために公開されています。公開によって再配布や派生作品の作成を許諾するものではありません。
[LICENSE](LICENSE) を参照してください。

第三者コンポーネント、同梱バイナリ、アセット、実行時データソース（公開脅威インテリジェンスフィード、
公開 IP→国データセット、ネイティブヘルパー内の Go 標準ライブラリ）は
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) に記載されています。

## アルファ版へのフィードバック

フィードバックは [GitHub Issues](https://github.com/visiongaiatechnology/gedefense_androidtv/issues) で歓迎します。
デバイスモデル、Android TV OS のバージョン、設定画面に表示されるアプリバージョンをお知らせください。
公開 issue に秘密情報、個人データ、悪用可能なセキュリティ詳細を投稿しないでください。
[SECURITY.md](SECURITY.md) を参照してください。

---

<p align="center"><i>GeDefense TV は VisionGaiaTechnology のプロジェクトです。<br>
「The humor is load-bearing. The code is not a joke.」</i></p>
