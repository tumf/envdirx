# envdirx

DJB `envdir` の1ファイル1変数を保ち、値だけ暗号化する CLI。既存の平文エントリも `run` で読めるため、段階移行できる。

```sh
uv sync
mkdir -p service.env
uv run envdirx init service.env
printf 'secret\n' | uv run envdirx set service.env API_TOKEN
uv run envdirx run service.env -- sh -c 'test -n "$API_TOKEN"'
```

既存の envdir を移行する場合は `uv run envdirx encrypt service.env`。指定した名前だけ暗号化するなら `uv run envdirx encrypt service.env API_TOKEN`。変換前に機密ファイルをバックアップし、変換後に動作確認する。`encrypt` はファイルをアトミックに置換するが、元の平文がディスクやバックアップから消去されたことは保証しない。

## 鍵と `.envdirx.key` ポインタ

`init` は公開鍵 `service.env/.envdirx.pub`（0644）、envdir の外の秘密鍵（既定は隣の `service.env.key`、`--key /secure/path/key` で変更可、0600）、そして秘密鍵の場所を指すポインタ `service.env/.envdirx.key`（0600）を作る。ポインタには秘密鍵の完全解決済み絶対パスと改行だけが入り、鍵のバイト列は入らない。親ディレクトリは自動作成せず、既存の公開鍵・秘密鍵・ポインタ（壊れたシンボリックリンクを含む）があれば何も書かずに失敗する。途中で失敗した場合は今回作ったファイルだけを削除する。**秘密鍵をリポジトリ、envdir、配布物に入れないこと。** 鍵を失うと復号できないので安全な別媒体へ保管する。

`run` は暗号化エントリがある場合だけ秘密鍵を読む。`--key` を指定すればポインタを読まずにその鍵を使い、指定しなければ `.envdirx.key` だけを見る（隣の `service.env.key` を推測するフォールバックはない）。`run` は DIRECTORY 以降をすべてコマンドとして扱うため、`--key` は必ず DIRECTORY より前に置く。

```sh
mkdir -p service.env
uv run envdirx init --key "$HOME/service.env.key" service.env
printf 'secret\n' | uv run envdirx set service.env API_TOKEN
uv run envdirx run --key "$HOME/service.env.key" service.env -- sh -c 'test "$API_TOKEN" = secret'
```

ポインタは次のどちらか。

- 通常ファイル: UTF-8 の1行のパス。末尾の LF/CRLF は1つだけ省略可。パス中の空白は保持する。空、複数行、NUL を含むもの、UTF-8 でないものは拒否する。先頭の `~/` はホームへ展開する。
- シンボリックリンク: リンク先を辿る。`~/` は展開しない。

相対パスはどちらも envdir 基準で解決するので、envdir と鍵をまとめて移動しても `../service.env.key` のような相対ポインタは有効なまま。`--key` の相対パスは従来どおりカレントディレクトリ基準で、先頭 `~/` を展開する。最終的な鍵はシンボリックリンクをすべて解決したうえで、解決済み envdir の外にある通常ファイル、実行ユーザー所有、グループ・その他の権限ビットなし（0600 など）でなければならない。ポインタや鍵が欠けている・壊れている・循環している・ディレクトリ・FIFO 等・権限や所有者が不正・鍵が不正なときは、子プロセスを起動せず鍵や値を表示せずに終了コード 111 で失敗する。平文だけの envdir はポインタも鍵も不要。

既存の envdir（ポインタ導入前の `service.env.key` を使うもの）は、ポインタを手で追加して移行する。再暗号化は不要。

```sh
printf '%s\n' "$PWD/service.env.key" > service.env/.envdirx.key
chmod 600 service.env/.envdirx.key
uv run envdirx run service.env -- true
```

シンボリックリンクにする場合:

```sh
rm -f service.env/.envdirx.key
ln -s ../service.env.key service.env/.envdirx.key
uv run envdirx run service.env -- true
```

`.gitignore` の `*.key` はポインタ `.envdirx.key` にも一致するので、ポインタもコミットされない。秘密鍵を守るこの除外は弱めないこと。**シンボリックリンクのポインタには注意**: `tar -h`、`rsync -L`、`cp -L` などリンクを辿るコピーやアーカイブで envdir を配布すると、ポインタの代わりに秘密鍵の中身がそのまま同梱される。配布する envdir には通常ファイルのポインタを使うか、`.envdirx.key` を除外する。

`set` と `encrypt` は公開鍵のみ必要で、`--key` は互換性のために受け付けるが使わない。鍵の上書き、鍵ローテーション、dotenvx のファイル形式との互換性はない。

## 実行時の意味

`run` はコマンドへ exec し終了コードを引き継ぐ。DJB方式に従い0バイトのエントリは環境変数を削除し、非空エントリは最初の行の末尾空白・タブを除去、NUL を改行へ変換する。暗号文は X25519 のエフェメラル鍵と ChaCha20-Poly1305 で暗号化し、ファイル名に認証を結びつける。`envdirx` は dotenvx と同じ**用途**だが、互換フォーマットではない。

```sh
uv run python -m unittest discover -s tests -v
```

`ponytail:` 現状はローカル POSIX 環境向け。敵対的なユーザーが同時にディレクトリを書き換えられる環境には対応しない。必要になったら dirfd を使った競合耐性と鍵管理を追加する。
