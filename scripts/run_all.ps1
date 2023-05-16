param (
    [Parameter(Mandatory=$true)][string]$data_dir
)

$base_dirs = Get-ChildItem -Path $data_dir -Directory -Force -ErrorAction SilentlyContinue

$counter = 0
foreach ($entry in $base_dirs) {
    $arr = $entry.FullName.Split("\")
    $base_path = "/usr/src/bridge/dataset/" + $arr[-3] + "/" + $arr[-2] + "/" + $arr[-1] + "/"
    $log_path = "E:\Academic\Georgia Tech\Projects\ECS\logs\" + $arr[-3] + "_" + $arr[-2] + "_" + $arr[-1] + "_" + [int](Get-Date -UFormat %s -Millisecond 0) + ".txt"
    $current_ = $arr[-3] + "/" + $arr[-2]
    echo "Running container #$counter in $current_"
    # echo $base_path
    docker run --mount type=bind,src="E:\Academic\Georgia Tech\Projects\ECS\bridge",target='/usr/src/bridge' -e BASE_PATH=$base_path kratos > $log_path
    docker container rm $(docker container ls -aq)
    $counter++
    if ($counter -eq 100) {
        break
    }
}