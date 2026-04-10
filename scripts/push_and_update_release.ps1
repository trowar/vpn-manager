param(
  [string]$Branch = "main",
  [string]$Tag = "latest",
  [string]$Repo = "trowar/vpn-manager",
  [string]$Token = "",
  [switch]$SkipPush
)

$ErrorActionPreference = "Stop"

if (-not $Token) {
  $Token = $env:GH_TOKEN
}
if (-not $Token) {
  $Token = $env:GITHUB_TOKEN
}
if (-not $Token) {
  throw "Missing GitHub token. Set GH_TOKEN or GITHUB_TOKEN, or pass -Token."
}

if (-not $SkipPush) {
  git push origin $Branch
}

git tag -f $Tag
git push origin ("refs/tags/" + $Tag) --force

$sha = (git rev-parse HEAD).Trim()
$subject = (git log -1 --pretty=%s).Trim()
$now = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")
$body = @"
自动更新于：$now
提交：$sha
说明：$subject
"@

$headers = @{
  Authorization = "Bearer $Token"
  Accept = "application/vnd.github+json"
  "X-GitHub-Api-Version" = "2022-11-28"
}

$payload = @{
  tag_name = $Tag
  target_commitish = $sha
  name = "Latest"
  body = $body
  draft = $false
  prerelease = $false
  make_latest = "true"
} | ConvertTo-Json -Depth 6

$base = "https://api.github.com/repos/$Repo"
$tagUrl = "$base/releases/tags/$Tag"

$release = $null
try {
  $release = Invoke-RestMethod -Method GET -Uri $tagUrl -Headers $headers
} catch {
  $statusCode = $null
  if ($_.Exception.Response) {
    $statusCode = [int]$_.Exception.Response.StatusCode
  }
  if ($statusCode -ne 404) {
    throw
  }
}

if ($release) {
  $updateUrl = "$base/releases/$($release.id)"
  $null = Invoke-RestMethod -Method PATCH -Uri $updateUrl -Headers $headers -Body $payload -ContentType "application/json"
  Write-Host "Release updated: $Tag"
} else {
  $null = Invoke-RestMethod -Method POST -Uri "$base/releases" -Headers $headers -Body $payload -ContentType "application/json"
  Write-Host "Release created: $Tag"
}
