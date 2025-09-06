# UPF eBPF Sampling Configuration API

這個 API 允許動態查看和更改 UPF eBPF 探針的 sample rate 設定。

## API 端點

### 1. 獲取當前 Sampling 配置

**GET** `/nwdaf-oam/sampling-config`

#### 響應示例：
```json
{
  "sample_rate": 100,
  "enabled": true
}
```

#### 狀態碼：
- `200 OK`: 成功獲取配置
- `503 Service Unavailable`: eBPF 未啟用或探針未初始化
- `500 Internal Server Error`: 讀取 eBPF map 失敗

### 2. 更新 Sampling 配置 (JSON 格式)

**PUT** `/nwdaf-oam/sampling-config`

#### 請求體：
```json
{
  "sample_rate": 50
}
```

#### 響應示例：
```json
{
  "sample_rate": 50,
  "enabled": true
}
```

#### 狀態碼：
- `200 OK`: 成功更新配置
- `400 Bad Request`: 請求格式錯誤或 sample rate 無效
- `503 Service Unavailable`: eBPF 未啟用或探針未初始化
- `500 Internal Server Error`: 更新 eBPF map 失敗

### 3. 更新 Sampling 配置 (URL 參數)

**PUT** `/nwdaf-oam/sampling-config/{rate}`

#### 示例：
```
PUT /nwdaf-oam/sampling-config/25
```

#### 響應示例：
```json
{
  "sample_rate": 25,
  "enabled": true
}
```

#### 狀態碼：
- `200 OK`: 成功更新配置
- `400 Bad Request`: URL 參數格式錯誤或 sample rate 無效
- `503 Service Unavailable`: eBPF 未啟用或探針未初始化
- `500 Internal Server Error`: 更新 eBPF map 失敗

## 使用說明

### Sample Rate 驗證
- Sample rate 必須大於 0
- 最大允許值為 1,000,000
- 驗證由 packet event reader 進行

### 數據來源
- **讀取**：直接從 kernel eBPF map (`sampling_control`) 讀取當前值
- **寫入**：直接更新 kernel eBPF map，立即生效
- 不依賴配置文件中的值，因為運行時可能已被修改

### 架構設計

```
API Layer (SBI)
    ↓ (sanity check)
Processor Layer
    ↓ (delegate)
eBPF Packet Event Reader
    ↓ (direct access)
Kernel eBPF Map
```

### 測試

使用提供的測試工具：
```bash
go run testtools/sampling_api_test.go
```

### cURL 示例

1. 獲取當前配置：
```bash
curl -X GET http://localhost:8888/nwdaf-oam/sampling-config
```

2. 更新配置 (JSON)：
```bash
curl -X PUT http://localhost:8888/nwdaf-oam/sampling-config \
  -H "Content-Type: application/json" \
  -d '{"sample_rate": 100}'
```

3. 更新配置 (URL 參數)：
```bash
curl -X PUT http://localhost:8888/nwdaf-oam/sampling-config/50
```

## 注意事項

1. **立即生效**：更改會立即應用到 kernel eBPF map
2. **不持久化**：重啟後會恢復到配置文件中的值
3. **線程安全**：API 操作是線程安全的
4. **錯誤處理**：提供詳細的錯誤信息和狀態碼

## 錯誤響應格式

```json
{
  "error": "Error description",
  "details": "Detailed error information"
}
```
