# đầu tiên là set up cho máy trước, chạy lệnh sau
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# tiếp theo thì cứ tạo file đuổi .ps1 là oke, rồi chạy mấy file này bằng lệnh cmd thôi

# Tự động add tất cả thay đổi
git add .

# Commit với thông điệp tự động
$commitMessage = "update files - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
git commit -m $commitMessage

# Push lên remote repository
git push -u origin master  # Hoặc thay bằng nhánh bạn đang sử dụng

# lệnh commit nhanh nè : ./backend/git-auto-push.ps1