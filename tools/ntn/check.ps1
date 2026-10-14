param([switch]$Build)
$ErrorActionPreference = 'Stop'
$ntnRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if ($Build) {
    docker build --tag day26-lab-checks:local --file "$PSScriptRoot/Dockerfile" $PSScriptRoot
    if ($LASTEXITCODE -ne 0) { throw 'Linux test image build failed' }
}
$ntnMount = "type=bind,source=$ntnRoot,target=/lab/workspace/Day26-Colosseum-Agent-Arena-Kit,readonly"
docker run --rm --network none --env 'PYTEST_ADDOPTS=-o cache_dir=/tmp/pytest-cache' --mount $ntnMount day26-lab-checks:local make test BIN=/usr/local/bin
if ($LASTEXITCODE -ne 0) { throw 'Public tests failed' }
docker run --rm --network none --mount $ntnMount day26-lab-checks:local python -m pytest student_tests/ -q -p no:cacheprovider --basetemp=/tmp/ntn-tests
if ($LASTEXITCODE -ne 0) { throw 'Student policy tests failed' }
