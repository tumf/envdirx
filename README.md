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

`init` は公開鍵 `service.env/.envdirx.pub` と秘密鍵 `service.env.key`（0600）を作る。**秘密鍵をリポジトリ、envdir、配布物に入れないこと。** `--key /secure/path/key` で任意の秘密鍵パスを指定できる。`set` と `encrypt` は公開鍵のみ必要。`run` は暗号化エントリがある場合だけ秘密鍵が必要。鍵を失うと復号できないので安全な別媒体へ保管する。鍵の上書き、鍵ローテーション、dotenvx のファイル形式との互換性はない。

`run` はコマンドへ exec し終了コードを引き継ぐ。DJB方式に従い0バイトのエントリは環境変数を削除し、非空エントリは最初の行の末尾空白・タブを除去、NUL を改行へ変換する。暗号文は X25519 のエフェメラル鍵と ChaCha20-Poly1305 で暗号化し、ファイル名に認証を結びつける。`envdirx` は dotenvx と同じ**用途**だが、互換フォーマットではない。

```sh
uv run python -m unittest discover -s tests -v
```

`ponytail:` 現状はローカル POSIX 環境向け。敵対的なユーザーが同時にディレクトリを書き換えられる環境には対応しない。必要になったら dirfd を使った競合耐性と鍵管理を追加する。
