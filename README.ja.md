# envdirx

DJB `envdir` の1ファイル1変数を保つ CLI。値は既定で平文のまま保存し、`set -c` を付けたものだけを暗号化する。平文と暗号文のエントリは同じディレクトリに混在でき、`run` はどちらも読む。暗号文はファイル名を変数名とし、ファイル内容を `encrypted:B...`（Base64テキスト）とする。例えば `GOG_KEYRING_PASSWORD` ファイルの中身が `encrypted:B...` となる。ファイル内に `GOG_KEYRING_PASSWORD=` は書かない。dotenvx と同じ暗号形式・鍵形式ではない。従来の `envdirx:v1:` 暗号文も読み込めるが、新規書き込みは新形式となり、末尾にLFを1つ付ける。改行なしの暗号文も読み込めるが、途中の改行、複数の末尾改行、CRLFは拒否する。

envdir は `-d/--directory DIRECTORY` で指定し、**サブコマンドより前**に置く。省略時はカレントディレクトリ基準の `./.envs`。ディレクトリを作るのは `mkdir` だけで、他のコマンドは既存のディレクトリを要求する。

```sh
uv sync
mkdir -p ~/.envdirx-keys
uv run envdirx mkdir
uv run envdirx keygen -K ~/.envdirx-keys
printf 'plain-value' | uv run envdirx set AAA
printf 'example-token' | uv run envdirx set -c API_TOKEN
uv run envdirx get AAA > /dev/null
uv run envdirx run -- sh -c 'test -n "$AAA" && test -n "$API_TOKEN"'
```

| コマンド | 動作 |
| --- | --- |
| `envdirx --version` / `envdirx -V` | インストール済み envdirx のバージョンと改行1つを出力して終了コード 0。`-d` と同じくサブコマンドより前に置き、envdir も鍵も不要 |
| `envdirx [-d D] mkdir` | 親を含めて作成。新規 envdir は 0700。既存ディレクトリは何も変えず成功、ディレクトリ以外があれば 111 |
| `envdirx [-d D] keygen (-k KEYFILE \| -K KEYDIR)` | 鍵ペアと `.envdirx.key` シンボリックリンクを作成 |
| `envdirx [-d D] set [-c] NAME` | 標準入力をそのまま保存（既定は平文、`-c` で暗号化） |
| `envdirx [-d D] get [--key KEY] NAME` | 値の元のバイト列を標準出力へ |
| `envdirx [-d D] encrypt (NAME [NAME ...] \| --all)` | 既存の平文エントリをその場で暗号化（公開鍵のみ使用） |
| `envdirx [-d D] decrypt [--key KEY] (NAME [NAME ...] \| --all)` | 暗号化エントリをその場で平文に戻す（秘密鍵のみ使用） |
| `envdirx [-d D] run [--key KEY] -- COMMAND [ARGS...]` | envdir を適用してコマンドを実行 |

明示的なディレクトリと鍵ファイルを使う例:

```sh
uv run envdirx -d service.env mkdir
uv run envdirx -d service.env keygen -k "$HOME/service.env.key"
printf 'example-token\n' | uv run envdirx -d service.env set -c API_TOKEN
uv run envdirx -d service.env run --key "$HOME/service.env.key" -- sh -c 'test "$API_TOKEN" = example-token'
```

値はシェルの引数ではなく標準入力から渡す。例の `sh -c '...'` は単一引用符で囲み、変数を呼び出し側のシェルで展開しない。

## `set`: 平文が既定、暗号化は `-c`

`set NAME` は標準入力のバイト列を一切変換せずアトミックに保存する（0600）。鍵もポインタも読まない。ただし `envdirx:` または `encrypted:` で始まる値は暗号文フォーマット用に予約されているので平文では保存できず、既存のエントリを変更せずに終了コード 111 で失敗する。そのような値は `set -c` で保存する。

`set -c NAME` は `.envdirx.pub` の公開鍵だけを使って暗号化する（秘密鍵は不要）。

## `encrypt` / `decrypt`: その場での変換

`encrypt` と `decrypt` は対象を必ず明示する。1つ以上のエントリ名か `--all` のどちらか一方が必須で、どちらもない・両方ある・同じ名前の重複は、ディレクトリや鍵を読む前に終了コード 2 で失敗する（引数なしで全エントリを暗号化する旧動作はない）。名前は `set`/`get` と同じ規則で検証し、`../X`、絶対パス、`.envdirx.pub` のようなドットファイルは何も書かずに 111 で拒否する。

- `encrypt` は平文を暗号化し、公開鍵 `.envdirx.pub` だけを使う。秘密鍵は読まない。
- `decrypt` は暗号文を認証付きで復号し、元のバイト列をそのまま書き戻す（改行・NUL・空ファイルも保持）。秘密鍵だけを使い、公開鍵は不要。鍵の探し方は `run`/`get` と同じで、`--key` はポインタより優先される。

名前を明示したエントリが既に目的の状態（`encrypt` なら暗号文、`decrypt` なら平文）だとエラー 111。`--all` は見えるエントリをすべて対象にし、既に変換済みのものは飛ばす。ドットファイル（鍵のメタデータを含む）には触れない。変換するものがなければ鍵を読まずに成功する。未対応・不正な `envdirx:` フォーマットはどちらの操作でも 111。

**`decrypt` は意図的に秘密を平文のままディスクへ書く。** 変換前に機密ファイルをバックアップし、変換後に動作確認する。ファイルはアトミックに置換するが、元の暗号文・平文がディスクやバックアップから消去されたことは保証しない。

復号した元の値が予約済みの `envdirx:` で始まる場合（`set -c` では保存できる）、そのまま平文に戻すと `get`/`run` が暗号文と誤認するので、`decrypt` はどのエントリも置換する前に 111 で失敗し暗号文を保持する。フォーマットの変更やエスケープはしない。そのような値が平文で必要なら、`get` の出力を envdir の外の適切な権限のファイルへリダイレクトする。

選択したエントリはすべて、最初の書き込みの前に読み込み・検証・変換をメモリ上で済ませる。エントリの欠落・通常ファイル以外・未対応フォーマット・鍵の不正・復号失敗・予約済みプレフィックスのどれかがあれば、何も変更せずに 111 で失敗する。その後、各エントリを個別にアトミック置換する（0600）。**バッチ全体のトランザクションではない**: 途中の書き込みで失敗した場合、それまでに置換したエントリは変換済みのまま残り、失敗したエントリは元のバイト列のまま 111 で終了する。成功時の標準出力は空で、エラーメッセージには名前とパスだけが含まれる。

```sh
printf 'old-plain' | uv run envdirx -d service.env set DB_PASSWORD
uv run envdirx -d service.env encrypt --all
uv run envdirx -d service.env run --key "$PWD/service.env.key" -- sh -c 'test "$DB_PASSWORD" = old-plain'
```

指定した名前だけを変換し、平文へ戻す例:

```sh
uv run envdirx -d app.env mkdir
uv run envdirx -d app.env keygen -k "$PWD/app.env.key"
printf 'db-secret' | uv run envdirx -d app.env set DB_PASSWORD
printf 'visible' | uv run envdirx -d app.env set LOG_LEVEL
uv run envdirx -d app.env encrypt DB_PASSWORD
test "$(cut -c 1-11 app.env/DB_PASSWORD)" = 'encrypted:B'
uv run envdirx -d app.env decrypt DB_PASSWORD
test "$(cat app.env/DB_PASSWORD)" = db-secret
uv run envdirx -d app.env encrypt --all
uv run envdirx -d app.env decrypt --key "$PWD/app.env.key" --all
test "$(cat app.env/LOG_LEVEL)" = visible
```

## `get`: 値をそのまま出力する

`get NAME` は平文ならそのバイト列、暗号文なら復号した元のバイト列を標準出力へ書く。改行を追加せず、`run` のような先頭行・末尾空白・NUL の変換もしない。空のエントリは0バイトを出力して成功する。**これは利用者の要求による明示的な秘密の表示**なので、端末やログに残る場所では使わないこと。エラーメッセージに値が含まれることはない。エントリがない・不正・未対応の `envdirx:` フォーマット・名前が一致しない暗号文・鍵が不正なときは、標準出力に何も書かず 111 で失敗する。`--key` は暗号化エントリにだけ使われ、ポインタより優先される。

```sh
uv run envdirx -d service.env mkdir
printf 'line\n' | uv run envdirx -d service.env set GREETING
test "$(uv run envdirx -d service.env get GREETING | od -An -c | tr -d ' ')" = 'line\n'
```

## 鍵と `.envdirx.key` ポインタ

`keygen` は次の3つを作る。

- 秘密鍵（0600）: `-k KEYFILE` ならそのファイル名、`-K KEYDIR` なら既存ディレクトリ内の `<公開鍵の生32バイトの SHA-256 小文字16進>.key`。どちらか一方が必須で、既定の保存先はない。
- 公開鍵 `.envdirx.pub`（0644、生の32バイト）。
- ポインタ `.envdirx.key`: 秘密鍵の完全解決済み絶対パスへのシンボリックリンク。

相対パスはカレントディレクトリ基準で、先頭の `~/` はホームへ展開する。`-k` は既存ディレクトリを指していてもファイル名として扱い、衝突として拒否する。秘密鍵・公開鍵・ポインタのどれかが既にあれば（壊れたシンボリックリンクを含む）何も書かずに失敗する。上書き・`-f/--force`・鍵ローテーションはない。鍵の親ディレクトリは作らず、保存先が解決済み envdir の中なら拒否する。途中で失敗した場合は今回作ったファイルだけを削除する。鍵の内容は表示しない。**秘密鍵をリポジトリ、envdir、配布物に入れないこと。** 鍵を失うと復号できないので安全な別媒体へ保管する。

`run` と `get` は暗号化エントリがある場合だけ秘密鍵を読む。`--key` を指定すればポインタを読まずにその鍵を使い（相対パスはカレントディレクトリ基準、先頭 `~/` を展開）、指定しなければ `.envdirx.key` だけを見る（隣の鍵を推測するフォールバックはない）。

ポインタは次のどちらか。

- シンボリックリンク: リンク先を辿る。`~/` は展開しない。
- 通常ファイル: UTF-8 の1行のパス。末尾の LF/CRLF は1つだけ省略可。パス中の空白は保持する。空、複数行、NUL を含むもの、UTF-8 でないものは拒否する。先頭の `~/` はホームへ展開する。

相対パスはどちらも envdir 基準で解決するので、envdir と鍵をまとめて移動しても `../service.env.key` のような相対ポインタは有効なまま。最終的な鍵はシンボリックリンクをすべて解決したうえで、解決済み envdir の外にある通常ファイル、実行ユーザー所有、グループ・その他の権限ビットなし（0600 など）でなければならない。ポインタや鍵が欠けている・壊れている・循環している・ディレクトリ・FIFO 等・権限や所有者が不正・鍵が不正なときは、子プロセスを起動せず鍵や値を表示せずに終了コード 111 で失敗する。平文だけの envdir はポインタも鍵も不要。

ポインタ導入前の envdir（隣の `service.env.key` を使うもの）は、ポインタを手で追加して移行する。再暗号化は不要。

```sh
printf '%s\n' "$PWD/service.env.key" > service.env/.envdirx.key
chmod 600 service.env/.envdirx.key
uv run envdirx -d service.env run -- true
```

シンボリックリンクにする場合:

```sh
rm -f service.env/.envdirx.key
ln -s ../service.env.key service.env/.envdirx.key
uv run envdirx -d service.env run -- true
```

`.gitignore` の `*.key` はポインタ `.envdirx.key` にも一致するので、ポインタもコミットされない。秘密鍵を守るこの除外は弱めないこと。**シンボリックリンクのポインタには注意**: `tar -h`、`rsync -L`、`cp -L` などリンクを辿るコピーやアーカイブで envdir を配布すると、ポインタの代わりに秘密鍵の中身がそのまま同梱される。配布する envdir には通常ファイルのポインタを使うか、`.envdirx.key` を除外する。

## `init` の廃止と移行

旧コマンド `init` は削除した。`init` を指定すると未知のサブコマンドとして終了コード 2 で失敗し、何も書かない。新しい envdir は `mkdir` と `keygen` で作る。

以前の `init` で作った envdir（通常ファイルのテキストポインタ `.envdirx.key` と隣の秘密鍵）は変換不要で、そのまま `run`・`get`・`set -c`・`encrypt`・`decrypt` で使える。テキストポインタを自動でシンボリックリンクへ書き換えることはない。

0.1.0 の正式リリース前に `set`・`encrypt`・`run` の位置引数ディレクトリは廃止した。旧形式は推測で受け付けないので、次のように書き換える。`set` が既定で暗号化しなくなった点に注意し、暗号化したい値には必ず `-c` を付ける。

| 旧 | 新 |
| --- | --- |
| `envdirx set DIR NAME` | `envdirx -d DIR set -c NAME` |
| `envdirx encrypt DIR [NAME ...]` | `envdirx -d DIR encrypt (NAME [NAME ...] \| --all)` |
| `envdirx encrypt`（引数なしで全平文を暗号化） | `envdirx encrypt --all` |
| `envdirx run [--key K] DIR -- CMD` | `envdirx -d DIR run [--key K] -- CMD` |
| `envdirx set --key K DIR NAME` / `encrypt --key K ...` | `--key` を外す（公開鍵しか使わない） |

## バージョンとリリース

`envdirx --version` はインストール済みディストリビューションのバージョンを表示する。バージョンを定義するのは `pyproject.toml` の `project.version` だけ。`run -- COMMAND --version` の `--version` はそのまま子コマンドへ渡る。

リリースは手動で、セマンティックバージョン `MAJOR.MINOR.PATCH` を使う。1.0 より前は、互換性のない CLI 変更で MINOR を、互換性のある追加・修正で PATCH を上げる。リリース手順は `uv version <version>`（`pyproject.toml` と `uv.lock` を同時に更新）、テスト実行、コミット、そのコミットへの `v<version>` タグ付け。タグの push とパッケージ公開は別途オペレーターが行う。

## 実行時の意味

`run` は `--` の後をすべて子コマンドとして扱うので、子コマンドのフラグ（`-d`、`--key` など）は envdirx に解釈されない。`--` は必須で、`--key` は `--` より前に置く。`--` またはコマンドがなければ子プロセスを起動せずに失敗する。`run` はコマンドへ exec し終了コードを引き継ぐ。DJB方式に従い0バイトのエントリは環境変数を削除し、非空エントリは最初の行の末尾空白・タブを除去、NUL を改行へ変換する。暗号文は X25519 のエフェメラル鍵と ChaCha20-Poly1305 で暗号化し、ファイル名に認証を結びつける。`envdirx` は dotenvx と同じ**用途**だが、互換フォーマットではない。

```sh
uv run python -m unittest discover -s tests -v
```

`ponytail:` 現状はローカル POSIX 環境向け。敵対的なユーザーが同時にディレクトリを書き換えられる環境には対応しない。必要になったら dirfd を使った競合耐性と鍵管理を追加する。
