# TypeScript 学習ガイド

このガイドでは、TypeScriptの基本から応用までを体系的に学ぶための情報を提供します。特にReactとの組み合わせや、実際のWebアプリケーション開発におけるTypeScriptの活用方法に焦点を当てています。

## 目次

1. [TypeScriptの基本](#typeScriptの基本)
2. [TypeScriptの型システム](#typeScriptの型システム)
3. [ReactとTypeScript](#reactとtypescript)
4. [非同期処理とTypeScript](#非同期処理とtypescript)
5. [フォーム処理とバリデーション](#フォーム処理とバリデーション)
6. [状態管理とTypeScript](#状態管理とtypescript)
7. [APIとの通信](#apiとの通信)
8. [テストとTypeScript](#テストとtypescript)
9. [ベストプラクティス](#ベストプラクティス)
10. [学習リソース](#学習リソース)

## TypeScriptの基本

### TypeScriptとは

TypeScriptはJavaScriptのスーパーセットであり、静的型付けと最新のECMAScript機能を提供するプログラミング言語です。Microsoft社によって開発され、大規模なアプリケーション開発に適しています。

### TypeScriptの利点

- **型安全性**: コンパイル時に型エラーを検出
- **IDEサポート**: コード補完、リファクタリング、ナビゲーションの強化
- **ドキュメント化**: コードの意図を明確に表現
- **バグの早期発見**: 実行前に多くの問題を検出
- **メンテナンス性の向上**: 特に大規模プロジェクトで効果を発揮

### 開発環境のセットアップ

1. **Node.jsとnpmのインストール**:
   ```bash
   # Node.jsのバージョン確認
   node -v
   npm -v
   ```

2. **TypeScriptのインストール**:
   ```bash
   npm install -g typescript
   tsc --version
   ```

3. **エディタの設定**:
   - Visual Studio Code: TypeScriptサポートが組み込み済み
   - 他のエディタ: TypeScript用プラグインをインストール

### 最初のTypeScriptプログラム

```typescript
// hello.ts
function greet(name: string): string {
  return `Hello, ${name}!`;
}

const message = greet("TypeScript");
console.log(message);
```

コンパイルと実行:

```bash
tsc hello.ts
node hello.js
```

### tsconfig.jsonの設定

プロジェクトのルートディレクトリに`tsconfig.json`ファイルを作成して、TypeScriptコンパイラの動作をカスタマイズできます:

```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "esnext",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "allowSyntheticDefaultImports": true,
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx"
  },
  "include": ["src"]
}
```

## TypeScriptの型システム

### 基本的な型

```typescript
// プリミティブ型
let isDone: boolean = false;
let decimal: number = 6;
let color: string = "blue";
let notSure: any = 4;
let u: undefined = undefined;
let n: null = null;

// 配列
let list1: number[] = [1, 2, 3];
let list2: Array<number> = [1, 2, 3];

// タプル
let tuple: [string, number] = ["hello", 10];

// enum
enum Color {Red, Green, Blue}
let c: Color = Color.Green;

// void
function warnUser(): void {
  console.log("This is a warning message");
}

// never
function error(message: string): never {
  throw new Error(message);
}
```

### インターフェース

インターフェースは、オブジェクトの形状を定義するための強力な方法です:

```typescript
interface User {
  id: number;
  name: string;
  email: string;
  age?: number; // オプショナルプロパティ
  readonly createdAt: Date; // 読み取り専用プロパティ
}

function createUser(user: User): User {
  return user;
}

const newUser: User = {
  id: 1,
  name: "John Doe",
  email: "john@example.com",
  createdAt: new Date()
};
```

### 型エイリアス

型エイリアスは、型に名前を付ける方法です:

```typescript
type ID = string | number;
type UserRole = "admin" | "user" | "guest";

interface User {
  id: ID;
  role: UserRole;
}
```

### ジェネリクス

ジェネリクスを使用すると、再利用可能な型定義を作成できます:

```typescript
// ジェネリック関数
function identity<T>(arg: T): T {
  return arg;
}

const output = identity<string>("myString");

// ジェネリッククラス
class GenericNumber<T> {
  zeroValue: T;
  add: (x: T, y: T) => T;
}

// ジェネリックインターフェース
interface Response<T> {
  data: T;
  status: number;
  message: string;
}

type UserResponse = Response<User>;
```

### 高度な型

TypeScriptには、より複雑な型を表現するための高度な機能があります:

```typescript
// ユニオン型
type Status = "pending" | "approved" | "rejected";

// インターセクション型
type Employee = Person & { employeeId: number };

// 型ガード
function isString(value: any): value is string {
  return typeof value === "string";
}

// マップ型
type Readonly<T> = {
  readonly [P in keyof T]: T[P];
};

// 条件付き型
type NonNullable<T> = T extends null | undefined ? never : T;
```

## ReactとTypeScript

### コンポーネントの型定義

```typescript
// 関数コンポーネント
interface ButtonProps {
  text: string;
  onClick: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary";
}

const Button: React.FC<ButtonProps> = ({ 
  text, 
  onClick, 
  disabled = false, 
  variant = "primary" 
}) => {
  return (
    <button 
      onClick={onClick} 
      disabled={disabled}
      className={`btn btn-${variant}`}
    >
      {text}
    </button>
  );
};

// クラスコンポーネント
interface CounterProps {
  initialCount: number;
}

interface CounterState {
  count: number;
}

class Counter extends React.Component<CounterProps, CounterState> {
  constructor(props: CounterProps) {
    super(props);
    this.state = {
      count: props.initialCount
    };
  }

  increment = () => {
    this.setState({ count: this.state.count + 1 });
  };

  render() {
    return (
      <div>
        <p>Count: {this.state.count}</p>
        <button onClick={this.increment}>Increment</button>
      </div>
    );
  }
}
```

### イベントハンドリング

```typescript
// イベントの型
const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
  console.log(event.target.value);
};

const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
  event.preventDefault();
  // フォーム送信処理
};

const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
  console.log("Button clicked");
};
```

### Hooks

```typescript
// useState
const [count, setCount] = useState<number>(0);
const [user, setUser] = useState<User | null>(null);

// useEffect
useEffect(() => {
  const fetchData = async () => {
    const response = await fetch('/api/data');
    const data: ApiResponse = await response.json();
    // ...
  };
  
  fetchData();
}, []);

// useRef
const inputRef = useRef<HTMLInputElement>(null);

// useReducer
type Action = 
  | { type: 'increment' }
  | { type: 'decrement' }
  | { type: 'reset', payload: number };

function reducer(state: number, action: Action): number {
  switch (action.type) {
    case 'increment':
      return state + 1;
    case 'decrement':
      return state - 1;
    case 'reset':
      return action.payload;
    default:
      return state;
  }
}

const [state, dispatch] = useReducer(reducer, 0);
```

### カスタムフック

```typescript
// カスタムフックの型定義
function useLocalStorage<T>(key: string, initialValue: T): [T, (value: T) => void] {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.log(error);
      return initialValue;
    }
  });

  const setValue = (value: T) => {
    try {
      setStoredValue(value);
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.log(error);
    }
  };

  return [storedValue, setValue];
}

// 使用例
const [name, setName] = useLocalStorage<string>("name", "");
```

### コンテキストAPI

```typescript
// コンテキストの型定義
interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = React.createContext<AuthContextType | undefined>(undefined);

// コンテキストプロバイダー
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);

  const login = async (username: string, password: string) => {
    // ログイン処理
    const userData = await loginApi(username, password);
    setUser(userData);
  };

  const logout = () => {
    // ログアウト処理
    setUser(null);
  };

  const value = {
    user,
    login,
    logout,
    isAuthenticated: !!user
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// カスタムフックでコンテキストを使用
export const useAuth = (): AuthContextType => {
  const context = React.useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
```

## 非同期処理とTypeScript

### Promise

```typescript
// Promiseの型定義
function fetchUser(id: number): Promise<User> {
  return fetch(`/api/users/${id}`)
    .then(response => {
      if (!response.ok) {
        throw new Error(response.statusText);
      }
      return response.json() as Promise<User>;
    });
}

// 使用例
fetchUser(1)
  .then(user => console.log(user.name))
  .catch(error => console.error(error));
```

### async/await

```typescript
// async/awaitの型定義
async function fetchUserData(id: number): Promise<User> {
  try {
    const response = await fetch(`/api/users/${id}`);
    if (!response.ok) {
      throw new Error(response.statusText);
    }
    return await response.json() as User;
  } catch (error) {
    console.error("Error fetching user:", error);
    throw error;
  }
}

// Reactコンポーネントでの使用例
const UserProfile: React.FC<{ userId: number }> = ({ userId }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadUser = async () => {
      try {
        setLoading(true);
        const userData = await fetchUserData(userId);
        setUser(userData);
        setError(null);
      } catch (err) {
        setError("Failed to load user data");
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    loadUser();
  }, [userId]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!user) return <div>No user found</div>;

  return (
    <div>
      <h1>{user.name}</h1>
      <p>Email: {user.email}</p>
    </div>
  );
};
```

### エラーハンドリング

```typescript
// カスタムエラークラス
class ApiError extends Error {
  constructor(
    public statusCode: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// エラーハンドリング
async function fetchData<T>(url: string): Promise<T> {
  try {
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new ApiError(
        response.status,
        `API error: ${response.status} ${response.statusText}`
      );
    }
    
    return await response.json() as T;
  } catch (error) {
    if (error instanceof ApiError) {
      // APIエラーの処理
      console.error(`API Error ${error.statusCode}: ${error.message}`);
    } else if (error instanceof Error) {
      // その他のエラーの処理
      console.error(`Error: ${error.message}`);
    } else {
      // 未知のエラーの処理
      console.error("Unknown error:", error);
    }
    throw error;
  }
}
```

## フォーム処理とバリデーション

### 基本的なフォーム

```typescript
// 基本的なフォーム
const SimpleForm: React.FC = () => {
  const [formData, setFormData] = useState({
    name: "",
    email: ""
  });
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    console.log(formData);
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="name">Name:</label>
        <input
          type="text"
          id="name"
          name="name"
          value={formData.name}
          onChange={handleChange}
        />
      </div>
      <div>
        <label htmlFor="email">Email:</label>
        <input
          type="email"
          id="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
        />
      </div>
      <button type="submit">Submit</button>
    </form>
  );
};
```

### react-hook-formの使用

```typescript
// react-hook-formの使用
import { useForm, SubmitHandler } from "react-hook-form";

interface FormInputs {
  name: string;
  email: string;
  age: number;
}

const HookForm: React.FC = () => {
  const { 
    register, 
    handleSubmit, 
    formState: { errors } 
  } = useForm<FormInputs>();
  
  const onSubmit: SubmitHandler<FormInputs> = (data) => {
    console.log(data);
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <div>
        <label htmlFor="name">Name:</label>
        <input
          id="name"
          {...register("name", { required: "Name is required" })}
        />
        {errors.name && <p>{errors.name.message}</p>}
      </div>
      
      <div>
        <label htmlFor="email">Email:</label>
        <input
          id="email"
          {...register("email", {
            required: "Email is required",
            pattern: {
              value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
              message: "Invalid email address"
            }
          })}
        />
        {errors.email && <p>{errors.email.message}</p>}
      </div>
      
      <div>
        <label htmlFor="age">Age:</label>
        <input
          id="age"
          type="number"
          {...register("age", {
            required: "Age is required",
            min: {
              value: 18,
              message: "You must be at least 18 years old"
            }
          })}
        />
        {errors.age && <p>{errors.age.message}</p>}
      </div>
      
      <button type="submit">Submit</button>
    </form>
  );
};
```

### フォームバリデーション

```typescript
// Zod（スキーマバリデーションライブラリ）を使用したバリデーション
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

// バリデーションスキーマ
const userSchema = z.object({
  username: z.string()
    .min(3, "Username must be at least 3 characters")
    .max(20, "Username must be at most 20 characters"),
  email: z.string()
    .email("Invalid email address"),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
  confirmPassword: z.string()
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"]
});

// 型の推論
type UserFormData = z.infer<typeof userSchema>;

// フォームコンポーネント
const RegistrationForm: React.FC = () => {
  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm<UserFormData>({
    resolver: zodResolver(userSchema)
  });
  
  const onSubmit = (data: UserFormData) => {
    console.log(data);
    // 登録処理
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {/* フォームフィールド */}
    </form>
  );
};
```

## 状態管理とTypeScript

### Redux Toolkit

```typescript
// スライスの定義
import { createSlice, PayloadAction } from "@reduxjs/toolkit";

interface CounterState {
  value: number;
  status: "idle" | "loading" | "failed";
}

const initialState: CounterState = {
  value: 0,
  status: "idle"
};

export const counterSlice = createSlice({
  name: "counter",
  initialState,
  reducers: {
    increment: (state) => {
      state.value += 1;
    },
    decrement: (state) => {
      state.value -= 1;
    },
    incrementByAmount: (state, action: PayloadAction<number>) => {
      state.value += action.payload;
    },
    setStatus: (state, action: PayloadAction<CounterState["status"]>) => {
      state.status = action.payload;
    }
  }
});

export const { increment, decrement, incrementByAmount, setStatus } = counterSlice.actions;
export default counterSlice.reducer;

// ストアの設定
import { configureStore } from "@reduxjs/toolkit";
import counterReducer from "./counterSlice";

export const store = configureStore({
  reducer: {
    counter: counterReducer
  }
});

// 型の推論
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// カスタムフック
import { TypedUseSelectorHook, useDispatch, useSelector } from "react-redux";

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

// コンポーネントでの使用
const Counter: React.FC = () => {
  const count = useAppSelector(state => state.counter.value);
  const status = useAppSelector(state => state.counter.status);
  const dispatch = useAppDispatch();
  
  return (
    <div>
      <div>
        <button onClick={() => dispatch(decrement())}>-</button>
        <span>{count}</span>
        <button onClick={() => dispatch(increment())}>+</button>
      </div>
      <div>
        <button onClick={() => dispatch(incrementByAmount(5))}>+5</button>
      </div>
      <div>Status: {status}</div>
    </div>
  );
};
```

### Context API

```typescript
// 状態管理用のコンテキスト
interface AppState {
  theme: "light" | "dark";
  language: "en" | "ja" | "fr";
}

interface AppContextType {
  state: AppState;
  setTheme: (theme: AppState["theme"]) => void;
  setLanguage: (language: AppState["language"]) => void;
}

const initialState: AppState = {
  theme: "light",
  language: "en"
};

const AppContext = React.createContext<AppContextType | undefined>(undefined);

// プロバイダーコンポーネント
export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<AppState>(initialState);
  
  const setTheme = (theme: AppState["theme"]) => {
    setState(prev => ({ ...prev, theme }));
  };
  
  const setLanguage = (language: AppState["language"]) => {
    setState(prev => ({ ...prev, language }));
  };
  
  const value = {
    state,
    setTheme,
    setLanguage
  };
  
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

// カスタムフック
export const useApp = (): AppContextType => {
  const context = React.useContext(AppContext);
  if (context === undefined) {
    throw new Error("useApp must be used within an AppProvider");
  }
  return context;
};

// 使用例
const ThemeToggle: React.FC = () => {
  const { state, setTheme } = useApp();
  
  const toggleTheme = () => {
    setTheme(state.theme === "light" ? "dark" : "light");
  };
  
  return (
    <button onClick={toggleTheme}>
      Current theme: {state.theme}
    </button>
  );
};
```

## APIとの通信

### Fetch API

```typescript
// 型定義
interface ApiResponse<T> {
  data: T;
  status: number;
  message: string;
}

interface User {
  id: number;
  name: string;
  email: string;
}

// APIクライアント
async function fetchUsers(): Promise<ApiResponse<User[]>> {
  const response = await fetch("/api/users");
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  return await response.json() as ApiResponse<User[]>;
}

async function fetchUser(id: number): Promise<ApiResponse<User>> {
  const response = await fetch(`/api/users/${id}`);
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  return await response.json() as ApiResponse<User>;
}

async function createUser(userData: Omit<User, "id">): Promise<ApiResponse<User>> {
  const response = await fetch("/api/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(userData)
  });
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  return await response.json() as ApiResponse<User>;
}
```

### Axios

```typescript
// Axiosの設定
import axios, { AxiosResponse, AxiosError } from "axios";

// インスタンスの作成
const api = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json"
  },
  timeout: 10000
});

// レスポンスの型
interface ApiResponse<T> {
  data: T;
  status: number;
  message: string;
}

// インターセプター
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // 認証エラー処理
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// APIクライアント
export const userApi = {
  getUsers: async (): Promise<User[]> => {
    const response = await api.get<ApiResponse<User[]>>("/users");
    return response.data.data;
  },
  
  getUser: async (id: number): Promise<User> => {
    const response = await api.get<ApiResponse<User>>(`/users/${id}`);
    return response.data.data;
  },
  
  createUser: async (userData: Omit<User, "id">): Promise<User> => {
    const response = await api.post<ApiResponse<User>>("/users", userData);
    return response.data.data;
  },
  
  updateUser: async (id: number, userData: Partial<User>): Promise<User> => {
    const response = await api.put<ApiResponse<User>>(`/users/${id}`, userData);
    return response.data.data;
  },
  
  deleteUser: async (id: number): Promise<void> => {
    await api.delete(`/users/${id}`);
  }
};
```

### React Query

```typescript
// React Queryの設定
import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from "react-query";
import { userApi } from "./api";

const queryClient = new QueryClient();

// プロバイダー
const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <UserList />
    </QueryClientProvider>
  );
};

// データ取得
const UserList: React.FC = () => {
  const { data, isLoading, error } = useQuery<User[], Error>(
    "users",
    userApi.getUsers
  );
  
  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return (
    <div>
      <h1>Users</h1>
      <ul>
        {data?.map(user => (
          <li key={user.id}>{user.name}</li>
        ))}
      </ul>
    </div>
  );
};

// データ更新
const CreateUserForm: React.FC = () => {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  
  const mutation = useMutation(
    (newUser: Omit<User, "id">) => userApi.createUser(newUser),
    {
      onSuccess: () => {
        // キャッシュの更新
        queryClient.invalidateQueries("users");
        // フォームのリセット
        setName("");
        setEmail("");
      }
    }
  );
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate({ name, email });
  };
  
  return (
    <form onSubmit={handleSubmit}>
      {/* フォームフィールド */}
      <button type="submit" disabled={mutation.isLoading}>
        {mutation.isLoading ? "Creating..." : "Create User"}
      </button>
    </form>
  );
};
```

## テストとTypeScript

### Jestの設定

```typescript
// jest.config.js
module.exports = {
  preset: "ts-jest",
  testEnvironment: "jsdom",
  setupFilesAfterEnv: ["@testing-library/jest-dom/extend-expect"],
  moduleNameMapper: {
    "\\.(css|less|scss|sass)$": "identity-obj-proxy"
  }
};
```

### コンポーネントのテスト

```typescript
// Button.test.tsx
import { render, screen, fireEvent } from "@testing-library/react";
import Button from "./Button";

describe("Button component", () => {
  test("renders with correct text", () => {
    const handleClick = jest.fn();
    render(<Button text="Click me" onClick={handleClick} />);
    
    const buttonElement = screen.getByText("Click me");
    expect(buttonElement).toBeInTheDocument();
  });
  
  test("calls onClick when clicked", () => {
    const handleClick = jest.fn();
    render(<Button text="Click me" onClick={handleClick} />);
    
    const buttonElement = screen.getByText("Click me");
    fireEvent.click(buttonElement);
    
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
  
  test("is disabled when disabled prop is true", () => {
    const handleClick = jest.fn();
    render(<Button text="Click me" onClick={handleClick} disabled={true} />);
    
    const buttonElement = screen.getByText("Click me");
    expect(buttonElement).toBeDisabled();
    
    fireEvent.click(buttonElement);
    expect(handleClick).not.toHaveBeenCalled();
  });
});
```

### フックのテスト

```typescript
// useCounter.test.ts
import { renderHook, act } from "@testing-library/react-hooks";
import useCounter from "./useCounter";

describe("useCounter hook", () => {
  test("should initialize with default value", () => {
    const { result } = renderHook(() => useCounter());
    expect(result.current.count).toBe(0);
  });
  
  test("should initialize with provided value", () => {
    const { result } = renderHook(() => useCounter(10));
    expect(result.current.count).toBe(10);
  });
  
  test("should increment counter", () => {
    const { result } = renderHook(() => useCounter());
    
    act(() => {
      result.current.increment();
    });
    
    expect(result.current.count).toBe(1);
  });
  
  test("should decrement counter", () => {
    const { result } = renderHook(() => useCounter(5));
    
    act(() => {
      result.current.decrement();
    });
    
    expect(result.current.count).toBe(4);
  });
  
  test("should reset counter", () => {
    const { result } = renderHook(() => useCounter(5));
    
    act(() => {
      result.current.reset();
    });
    
    expect(result.current.count).toBe(0);
  });
});
```

### モックの使用

```typescript
// api.test.ts
import { userApi } from "./api";
import axios from "axios";

// axiosのモック
jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("userApi", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });
  
  test("getUsers should fetch users successfully", async () => {
    const users = [
      { id: 1, name: "John Doe", email: "john@example.com" },
      { id: 2, name: "Jane Doe", email: "jane@example.com" }
    ];
    
    mockedAxios.get.mockResolvedValueOnce({
      data: { data: users, status: 200, message: "Success" }
    });
    
    const result = await userApi.getUsers();
    
    expect(mockedAxios.get).toHaveBeenCalledWith("/users");
    expect(result).toEqual(users);
  });
  
  test("createUser should create a user successfully", async () => {
    const newUser = { name: "John Doe", email: "john@example.com" };
    const createdUser = { id: 1, ...newUser };
    
    mockedAxios.post.mockResolvedValueOnce({
      data: { data: createdUser, status: 201, message: "Created" }
    });
    
    const result = await userApi.createUser(newUser);
    
    expect(mockedAxios.post).toHaveBeenCalledWith("/users", newUser);
    expect(result).toEqual(createdUser);
  });
  
  test("getUser should handle errors", async () => {
    mockedAxios.get.mockRejectedValueOnce(new Error("Network Error"));
    
    await expect(userApi.getUser(1)).rejects.toThrow("Network Error");
  });
});
```

## ベストプラクティス

### 型の命名規則

- インターフェース名は名詞または形容詞で始める: `User`, `Readable`
- 型エイリアス名は名詞または形容詞で始める: `UserRole`, `ApiResponse`
- ジェネリック型パラメータは単一の大文字または記述的な名前を使用: `T`, `TData`, `ItemType`

### 型の使い分け

- **インターフェース**: オブジェクトの形状を定義する場合や、クラスが実装すべき契約を定義する場合
- **型エイリアス**: ユニオン型、交差型、プリミティブ型のエイリアスを定義する場合
- **enum**: 関連する定数のグループを定義する場合
- **const assertion**: 文字列リテラルの集合を定義する場合

```typescript
// インターフェース
interface User {
  id: number;
  name: string;
}

// 型エイリアス
type UserRole = "admin" | "user" | "guest";

// enum
enum Direction {
  Up,
  Down,
  Left,
  Right
}

// const assertion
const COLORS = ["red", "green", "blue"] as const;
type Color = typeof COLORS[number]; // "red" | "green" | "blue"
```

### 型安全性の向上

- `any`型の使用を避ける
- `unknown`型を使用して型安全性を確保する
- 型ガードを使用して型の絞り込みを行う
- `readonly`修飾子を使用して不変性を確保する
- `Partial<T>`, `Required<T>`, `Pick<T, K>`, `Omit<T, K>`などのユーティリティ型を活用する

```typescript
// anyの代わりにunknownを使用
function processValue(value: unknown): string {
  // 型ガードで型を絞り込む
  if (typeof value === "string") {
    return value.toUpperCase();
  }
  if (typeof value === "number") {
    return value.toString();
  }
  throw new Error("Unsupported value type");
}

// readonlyの使用
interface Config {
  readonly apiUrl: string;
  readonly timeout: number;
}

// ユーティリティ型の活用
interface User {
  id: number;
  name: string;
  email: string;
  age: number;
}

type UserCreationParams = Omit<User, "id">;
type UserUpdateParams = Partial<User>;
type UserBasicInfo = Pick<User, "id" | "name">;
```

### エラー処理

- 具体的なエラー型を定義する
- エラーの型を絞り込むための型ガードを使用する
- `try/catch`ブロックでエラーを適切に処理する

```typescript
// カスタムエラークラス
class ValidationError extends Error {
  constructor(
    public field: string,
    message: string
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

// 型ガード
function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

function isNotFoundError(error: unknown): error is NotFoundError {
  return error instanceof NotFoundError;
}

// エラー処理
async function fetchData() {
  try {
    const data = await api.getData();
    return data;
  } catch (error) {
    if (isValidationError(error)) {
      console.error(`Validation error in field ${error.field}: ${error.message}`);
    } else if (isNotFoundError(error)) {
      console.error(`Not found: ${error.message}`);
    } else if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
    } else {
      console.error("Unknown error:", error);
    }
    throw error;
  }
}
```

### パフォーマンスの最適化

- 不必要な再レンダリングを避けるために`React.memo`、`useMemo`、`useCallback`を使用する
- 大きなデータセットを処理する場合は仮想化を検討する
- 型の計算コストを削減するために型のキャッシュを活用する

```typescript
// メモ化されたコンポーネント
const MemoizedComponent = React.memo<Props>(
  ({ value, onChange }) => {
    return <div>{/* ... */}</div>;
  },
  (prevProps, nextProps) => {
    // カスタム比較関数
    return prevProps.value === nextProps.value;
  }
);

// メモ化された値
const memoizedValue = useMemo(() => {
  return computeExpensiveValue(a, b);
}, [a, b]);

// メモ化されたコールバック
const memoizedCallback = useCallback(() => {
  doSomething(a, b);
}, [a, b]);
```

## 学習リソース

### 公式ドキュメント

- [TypeScript公式ドキュメント](https://www.typescriptlang.org/docs/)
- [React TypeScriptチートシート](https://react-typescript-cheatsheet.netlify.app/)

### 書籍

- 『プログラミングTypeScript』 Boris Cherny著
- 『Effective TypeScript』 Dan Vanderkam著

### オンラインコース

- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)
- [Udemy: Understanding TypeScript](https://www.udemy.com/course/understanding-typescript/)
- [Frontend Masters: TypeScript Fundamentals](https://frontendmasters.com/courses/typescript-v3/)

### ブログとチュートリアル

- [TypeScript Evolution](https://mariusschulz.com/blog/series/typescript-evolution)
- [TypeScript Weekly](https://www.typescript-weekly.com/)
- [React+TypeScriptチュートリアル](https://react-typescript-tutorial.netlify.app/)

### コミュニティとフォーラム

- [TypeScript GitHub](https://github.com/microsoft/TypeScript)
- [Stack Overflow - TypeScript](https://stackoverflow.com/questions/tagged/typescript)
- [Reddit - TypeScript](https://www.reddit.com/r/typescript/)

### ツールとプレイグラウンド

- [TypeScript Playground](https://www.typescriptlang.org/play)
- [TS Config Reference](https://www.typescriptlang.org/tsconfig)
- [Type Challenges](https://github.com/type-challenges/type-challenges)
