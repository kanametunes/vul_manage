# 脆弱性とたたかおう
脆弱性情報がTwitterに流れてきて、よくわからんまま対応するのはキリがなくて大変なので、まじヤバいやつだけ通知してほしい気持ちです

## これでできる事
Google Apps Scriptを使って、NVDから脆弱性情報の取得
  - 更新日時を指定
  - Severityを指定
  - Attack Vectorを指定
  - Productを指定
  - などなど

## 使い方
GASにそのまま貼ってください。
SlackのURL変えてね

## こんな感じでSlackに通知される
<img width="1117" alt="image" src="https://user-images.githubusercontent.com/66484626/151504308-6eb7b077-b9cb-4ac5-a336-7500995ffaaf.png">

やってみたんだけど…

## 結論
自社のシステムにはNessusとか脆弱性管理のツール入れるのが楽やんね
