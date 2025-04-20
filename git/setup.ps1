git branch

git checkout -b master # thay chữ master thành cái branch ông đã tạo mới trên githubb

git pull origin master


git add .

$commitMessage = "update files - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
git commit -m $commitMessage

# Push lên remote repository
git push -u origin master  # Hoặc thay bằng nhánh bạn đang sử dụng

# lệnh commit nhanh nè : ./gp.ps1