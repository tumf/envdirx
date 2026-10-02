# envdirx

DJB `envdir` の1ファイル1変数を保つ CLI。値は既定で平文のまま保存し、`set -c` を付けたものだけを暗号化する。平文と暗号文のエントリは同じディレクトリに混在でき、`run` はどちらも読む。

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
| `envdirx [-d D] mkdir` | 親を含めて作成。新規 envdir は 0700。既存ディレクトリは何も変えず成功、ディレクトリ以外があれば 111 |
| `envdirx [-d D] keygen (-k KEYFILE \| -K KEYDIR)` | 鍵ペアと `.envdirx.key` シンボリックリンクを作成 |
| `envdirx [-d D] set [-c] NAME` | 標準入力をそのまま保存（既定は平文、`-c` で暗号化） |
| `envdirx [-d D] get [--key KEY] NAME` | 値の元のバイト列を標準出力へ |
| `envdirx [-d D] encrypt [NAME ...]` | 既存の平文エントリをその場で暗号化（公開鍵のみ使用） |
| `envdirx [-d D] run [--key KEY] -- COMMAND [ARGS...]` | envdir を適用してコマンドを実行 |
| `envdirx init [--key KEY] DIRECTORY` | 旧コマンド（後述）。`-d` は指定できない |

明示的なディレクトリと鍵ファイルを使う例:

```sh
uv run envdirx -d service.env mkdir
uv run envdirx -d service.env keygen -k "$HOME/service.env.key"
printf 'example-token\n' | uv run envdirx -d service.env set -c API_TOKEN
uv run envdirx -d service.env run --key "$HOME/service.env.key" -- sh -c 'test "$API_TOKEN" = example-token'
```

値はシェルの引数ではなく標準入力から渡す。例の `sh -c '...'` は単一引用符で囲み、変数を呼び出し側のシェルで展開しない。

## `set`: 平文が既定、暗号化は `-c`

`set NAME` は標準入力のバイト列を一切変換せずアトミックに保存する（0600）。鍵もポインタも読まない。ただし `envdirx:` で始まる値は暗号文フォーマット用に予約されているので平文では保存できず、既存のエントリを変更せずに終了コード 111 で失敗する。そのような値は `set -c` で保存する。

`set -c NAME` は `.envdirx.pub` の公開鍵だけを使って暗号化する（秘密鍵は不要）。`encrypt` も同じく公開鍵のみで、既に暗号化されたエントリは変更しない（名前を明示した場合はエラー）。

既存の envdir を暗号化へ移行する場合は `uv run envdirx -d service.env encrypt`、指定した名前だけなら `uv run envdirx -d service.env encrypt API_TOKEN`。変換前に機密ファイルをバックアップし、変換後に動作確認する。`encrypt` はファイルをアトミックに置換するが、元の平文がディスクやバックアップから消去されたことは保証しない。

```sh
printf 'old-plain' | uv run envdirx -d service.env set DB_PASSWORD
uv run envdirx -d service.env encrypt
uv run envdirx -d service.env run --key "$PWD/service.env.key" -- sh -c 'test "$DB_PASSWORD" = old-plain'
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

## 旧コマンド `init` と移行

`init [--key KEY] DIRECTORY` は互換のために残した旧コマンドで、位置引数の DIRECTORY を取る。グローバルな `-d/--directory` と組み合わせると何も書かずに終了コード 2 で失敗する。公開鍵、秘密鍵（既定は隣の `DIRECTORY.key`、`--key` で変更可、0600）、そして秘密鍵の絶対パスと改行だけを入れた通常ファイルのポインタ（0600、シンボリックリンクではない）を作る。既存ファイルは上書きしない。新しく始めるなら `mkdir` と `keygen` を使う。

```sh
mkdir -p legacy.env
uv run envdirx init legacy.env
printf 'example-token' | uv run envdirx -d legacy.env set -c API_TOKEN
uv run envdirx -d legacy.env run -- sh -c 'test -n "$API_TOKEN"'
```

0.1.0 の正式リリース前に `set`・`encrypt`・`run` の位置引数ディレクトリは廃止した。旧形式は推測で受け付けないので、次のように書き換える。`set` が既定で暗号化しなくなった点に注意し、暗号化したい値には必ず `-c` を付ける。

| 旧 | 新 |
| --- | --- |
| `envdirx set DIR NAME` | `envdirx -d DIR set -c NAME` |
| `envdirx encrypt DIR [NAME ...]` | `envdirx -d DIR encrypt [NAME ...]` |
| `envdirx run [--key K] DIR -- CMD` | `envdirx -d DIR run [--key K] -- CMD` |
| `envdirx set --key K DIR NAME` / `encrypt --key K ...` | `--key` を外す（公開鍵しか使わない） |

既存の `init` で作った envdir と鍵はそのまま新しい文法で使える。

## 実行時の意味

`run` は `--` の後をすべて子コマンドとして扱うので、子コマンドのフラグ（`-d`、`--key` など）は envdirx に解釈されない。`--` は必須で、`--key` は `--` より前に置く。`--` またはコマンドがなければ子プロセスを起動せずに失敗する。`run` はコマンドへ exec し終了コードを引き継ぐ。DJB方式に従い0バイトのエントリは環境変数を削除し、非空エントリは最初の行の末尾空白・タブを除去、NUL を改行へ変換する。暗号文は X25519 のエフェメラル鍵と ChaCha20-Poly1305 で暗号化し、ファイル名に認証を結びつける。`envdirx` は dotenvx と同じ**用途**だが、互換フォーマットではない。

```sh
uv run python -m unittest discover -s tests -v
```

`ponytail:` 現状はローカル POSIX 環境向け。敵対的なユーザーが同時にディレクトリを書き換えられる環境には対応しない。必要になったら dirfd を使った競合耐性と鍵管理を追加する。
