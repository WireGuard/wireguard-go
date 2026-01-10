# WireGuardについて学ぶ

学習内容などを記録して行きます。目標としては、表面的でもいいので理解をしたい。いずれはC言語で書かれたコードのカーネル周辺も理解したい。

## 参考文献

- [WireGuard](https://www.wireguard.com/)
- [WireGuardのソースコード](https://git.zx2c4.com/wireguard-go)

## 学習内容

まずはdevice/device.go, device/receive.go, device/peer.goなどが面白そう。

Gemini 「Go言語における interface と struct の違いは、WireGuardのような大規模なコードを読む上で非常に重要なポイントです。
結論から言うと、struct は「実体（データとその持ち方）」であり、interface は「振る舞い（何ができるか）」を定義(ルールや規約)します。」

