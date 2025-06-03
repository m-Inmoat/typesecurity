# TypeScript & Spring Security サンプルアプリケーション アーキテクチャ設計

## 1. 全体アーキテクチャ

このサンプルアプリケーションは、モダンなWeb開発の標準的なアーキテクチャである「SPAフロントエンド + RESTful APIバックエンド」の構成を採用します。

```
[クライアント層]
    TypeScript + React SPA
            ↓ HTTP/REST
[API層]
    Spring Boot + Spring Security
            ↓ JPA
[データ層]
    H2 Database (開発用)
```

## 2. フロントエンド技術スタック

### コア技術
- **TypeScript 5.x**: 静的型付けによる安全なJavaScript開発
- **React 18.x**: UIコンポーネントライブラリ
- **React Router 6.x**: クライアントサイドルーティング

### 状態管理
- **React Context API**: アプリケーション状態の管理
- **React Hooks**: コンポーネントのライフサイクルと状態管理

### HTTP通信
- **Axios**: RESTful APIとの通信

### UI/UXコンポーネント
- **Material-UI (MUI) 5.x**: Reactコンポーネントライブラリ
- **React Hook Form**: フォーム管理と検証

### 開発ツール
- **Vite**: 高速な開発環境とビルドツール
- **ESLint**: コード品質とスタイルの一貫性確保
- **Jest + React Testing Library**: ユニットテストとコンポーネントテスト

## 3. バックエンド技術スタック

### コア技術
- **Java 17**: 最新のLTS版Java
- **Spring Boot 3.x**: アプリケーションフレームワーク
- **Spring Security 6.x**: セキュリティフレームワーク

### データアクセス
- **Spring Data JPA**: データアクセス層
- **Hibernate**: ORMフレームワーク
- **H2 Database**: インメモリデータベース（開発用）

### API開発
- **Spring Web**: RESTful API開発
- **Spring Validation**: 入力検証

### セキュリティ
- **JWT (JSON Web Token)**: トークンベースの認証
- **CORS設定**: クロスオリジンリソース共有の制御
- **BCrypt**: パスワードハッシュ化

### 開発ツール
- **Maven**: 依存関係管理とビルド
- **JUnit 5 + Mockito**: テストフレームワーク
- **Lombok**: ボイラープレートコード削減

## 4. データモデル

### 主要エンティティ

#### User
- id: Long (PK)
- username: String
- email: String
- password: String (ハッシュ化)
- roles: Set<Role>
- createdAt: LocalDateTime
- updatedAt: LocalDateTime

#### Role
- id: Long (PK)
- name: String (ROLE_ADMIN, ROLE_USER)

#### Task
- id: Long (PK)
- title: String
- description: String
- status: String (TODO, IN_PROGRESS, DONE)
- priority: String (LOW, MEDIUM, HIGH)
- dueDate: LocalDate
- owner: User (FK)
- assignees: Set<User> (多対多)
- createdAt: LocalDateTime
- updatedAt: LocalDateTime

## 5. API設計

### 認証API
- `POST /api/auth/register`: ユーザー登録
- `POST /api/auth/login`: ログイン（JWTトークン取得）
- `POST /api/auth/refresh`: トークンリフレッシュ
- `POST /api/auth/logout`: ログアウト

### ユーザーAPI
- `GET /api/users`: ユーザー一覧取得 (ADMIN)
- `GET /api/users/{id}`: ユーザー詳細取得
- `PUT /api/users/{id}`: ユーザー情報更新
- `DELETE /api/users/{id}`: ユーザー削除 (ADMIN)

### タスクAPI
- `GET /api/tasks`: タスク一覧取得
- `GET /api/tasks/{id}`: タスク詳細取得
- `POST /api/tasks`: タスク作成
- `PUT /api/tasks/{id}`: タスク更新
- `DELETE /api/tasks/{id}`: タスク削除
- `GET /api/tasks/user/{userId}`: ユーザーのタスク一覧取得

## 6. セキュリティ設計

### 認証フロー
1. ユーザーがログインフォームから認証情報を送信
2. バックエンドがユーザー情報を検証
3. 認証成功時、JWTトークンを生成して返却
4. フロントエンドがトークンをローカルストレージに保存
5. 以降のAPIリクエストにトークンを含めて送信
6. バックエンドがトークンを検証してリクエストを処理

### 認可設計
- **ロールベースアクセス制御 (RBAC)**: ユーザーロールに基づいたアクセス制御
- **メソッドレベルセキュリティ**: `@PreAuthorize` アノテーションによる細かい権限制御
- **リソースオーナーシップ**: 自分のリソースのみ編集可能

### セキュリティ対策
- **CSRF対策**: JWTベースの認証でCSRF保護
- **XSS対策**: 入力検証とサニタイズ
- **CORS設定**: 許可されたオリジンからのリクエストのみ受け付け
- **レート制限**: 過剰なリクエストの制限（オプション）

## 7. フロントエンドアーキテクチャ

### コンポーネント構造
```
src/
├── assets/         # 静的ファイル
├── components/     # 再利用可能なコンポーネント
│   ├── common/     # 共通UI要素
│   ├── auth/       # 認証関連コンポーネント
│   ├── tasks/      # タスク関連コンポーネント
│   └── users/      # ユーザー関連コンポーネント
├── contexts/       # React Context
├── hooks/          # カスタムフック
├── interfaces/     # TypeScript型定義
├── pages/          # ページコンポーネント
├── services/       # APIサービス
├── utils/          # ユーティリティ関数
└── App.tsx         # ルートコンポーネント
```

### ルーティング設計
- `/`: ホームページ/ダッシュボード
- `/login`: ログインページ
- `/register`: ユーザー登録ページ
- `/profile`: ユーザープロファイル
- `/tasks`: タスク一覧
- `/tasks/:id`: タスク詳細
- `/admin/users`: ユーザー管理（管理者のみ）

## 8. バックエンドアーキテクチャ

### パッケージ構造
```
com.example.taskmanager/
├── config/             # 設定クラス
│   ├── SecurityConfig.java
│   └── WebConfig.java
├── controller/         # APIコントローラー
├── dto/                # データ転送オブジェクト
├── exception/          # 例外クラス
├── model/              # エンティティクラス
├── repository/         # データアクセス層
├── security/           # セキュリティ関連クラス
│   ├── jwt/            # JWT関連
│   └── service/        # セキュリティサービス
├── service/            # ビジネスロジック
└── TaskManagerApplication.java
```

## 9. 開発・デプロイメント計画

### 開発環境
- **フロントエンド**: Node.js環境でのローカル開発
- **バックエンド**: Java環境でのローカル開発
- **データベース**: H2インメモリデータベース

### 開発フロー
1. バックエンドAPIの実装
2. フロントエンドの実装
3. 統合テスト
4. ドキュメント作成

### デプロイメント（オプション）
- **フロントエンド**: 静的ファイルのホスティング（Netlify, Vercel等）
- **バックエンド**: コンテナ化（Docker）とクラウドデプロイ

## 10. 学習ポイント

### TypeScript学習ポイント
- 型定義とインターフェース
- ジェネリクス
- 非同期処理（Promise, async/await）
- ReactとTypeScriptの統合
- 型安全なAPIクライアント

### Spring Security学習ポイント
- 認証プロセスのカスタマイズ
- JWTフィルターの実装
- メソッドレベルのセキュリティ
- ロールベースのアクセス制御
- セキュリティコンテキストの活用
