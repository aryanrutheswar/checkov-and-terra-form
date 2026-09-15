const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const websiteDir = path.resolve(__dirname, '../website');
const targetDist = path.resolve(__dirname, 'dist');

if (fs.existsSync(websiteDir)) {
  console.log('Building website from:', websiteDir);
  const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/sh';
  execSync('npm install; npm run build', { cwd: websiteDir, stdio: 'inherit', shell });
  const srcDist = path.join(websiteDir, 'dist');
  if (fs.existsSync(srcDist)) {
    fs.mkdirSync(targetDist, { recursive: true });
    fs.cpSync(srcDist, targetDist, { recursive: true });
    console.log('Successfully mirrored dist to:', targetDist);
  }
} else {
  console.error('Error: ../website directory not found');
  process.exit(1);
}
