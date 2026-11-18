(
  set -o pipefail
  git -C "$SOURCE_FOLDER" ls-files -z -- '*.go' go.mod go.sum .traefik.yml vendor LICENSE |
    tar -C "$SOURCE_FOLDER" --null -T - -cf - |
    tar -C "$TMPFOLDER" -xf -
)
