# 强制设置执行策略
Set-ExecutionPolicy Bypass -Scope Process -Force

# 确保在项目根目录
$projectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { $pwd }
cd $projectRoot

# 创建必要目录
New-Item -ItemType Directory -Force -Path ./circuits,./circuits/poseidon2_js | Out-Null

# 1. 编译电路（添加--verbose查看详细错误）
Write-Host "Step 1: Compiling circuit..." -ForegroundColor Green
circom2 ./circuits/poseidon2.circom --r1cs --wasm --sym --output ./circuits --verbose
if ($LASTEXITCODE -ne 0) { 
    Write-Host "Compilation failed. Check:" -ForegroundColor Red
    Write-Host "1. File permissions"
    Write-Host "2. circom2 is installed (npm install -g circom2)"
    exit 1 
}

# 其余步骤保持不变...

# 2. 生成见证
Write-Host "Step 2: Generating witness..." -ForegroundColor Green
node ./circuits/poseidon2_js/generate_witness.js `
    ./circuits/poseidon2_js/poseidon2.wasm `
    ./circuits/input.json `
    ./circuits/witness.wtns
if ($LASTEXITCODE -ne 0) { exit 1 }

# 3. Powers of Tau 初始化
Write-Host "Step 3: Starting Powers of Tau ceremony..." -ForegroundColor Green
snarkjs powersoftau new bn128 12 ./circuits/pot12_0000.ptau -v
if ($LASTEXITCODE -ne 0) { exit 1 }

# 4. 贡献随机性 (可替换为预生成的ptau文件)
Write-Host "Step 4: Contributing to PoT..." -ForegroundColor Green
snarkjs powersoftau contribute `
    ./circuits/pot12_0000.ptau `
    ./circuits/pot12_0001.ptau `
    --name="First Contributor" -v
if ($LASTEXITCODE -ne 0) { exit 1 }

# 5. 准备Phase 2
Write-Host "Step 5: Preparing Phase 2..." -ForegroundColor Green
snarkjs powersoftau prepare phase2 `
    ./circuits/pot12_0001.ptau `
    ./circuits/pot12_final.ptau -v
if ($LASTEXITCODE -ne 0) { exit 1 }

# 6. Groth16 zKey生成
Write-Host "Step 6: Generating zKey..." -ForegroundColor Green
snarkjs groth16 setup `
    ./circuits/poseidon2.r1cs `
    ./circuits/pot12_final.ptau `
    ./circuits/poseidon2_0000.zkey
if ($LASTEXITCODE -ne 0) { exit 1 }

# 7. zKey贡献 (可选)
Write-Host "Step 7: Contributing to zKey..." -ForegroundColor Green
snarkjs zkey contribute `
    ./circuits/poseidon2_0000.zkey `
    ./circuits/poseidon2_0001.zkey `
    --name="Second Contributor" -v
if ($LASTEXITCODE -ne 0) { exit 1 }

# 8. 导出验证密钥
Write-Host "Step 8: Exporting verification key..." -ForegroundColor Green
snarkjs zkey export verificationkey `
    ./circuits/poseidon2_0001.zkey `
    ./circuits/verification_key.json
if ($LASTEXITCODE -ne 0) { exit 1 }

# 9. 生成证明
Write-Host "Step 9: Generating proof..." -ForegroundColor Green
snarkjs groth16 prove `
    ./circuits/poseidon2_0001.zkey `
    ./circuits/witness.wtns `
    ./circuits/proof.json `
    ./circuits/public.json
if ($LASTEXITCODE -ne 0) { exit 1 }

# 10. 验证证明
Write-Host "Step 10: Verifying proof..." -ForegroundColor Green
snarkjs groth16 verify `
    ./circuits/verification_key.json `
    ./circuits/public.json `
    ./circuits/proof.json
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "All steps completed successfully!" -ForegroundColor Cyan