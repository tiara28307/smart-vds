const os = require('os')
const path = require('path')

// File path to user's `Download` directory
const filePath = path.join(os.homedir(), 'Downloads')
const downloadFilePath = `${filePath}/smart-vds-report.pdf`

module.exports = { downloadFilePath }
