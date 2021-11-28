const fs = require('fs')
const PDFDocument = require('pdfkit-table')

const doc = new PDFDocument({ size: 'A4' })
const vulnInfo = require('./vulnerabilityInfo')

/* downloadReport function
*       Purpose: To generate pdf version of Smart VDS Report for user to download
*       Tasks Executed By Function:
*           - Create pdf document with vulnerabilities detected information
*           - Return file path to downloaded report
* */
const downloadReport = async (downloadFilePath) => {
  const vulnerabilities = vulnInfo.getVulnInformation()
  const totalVulnerabilityCount = vulnInfo.getTotalVulnCount()

  // Get file path for download
  const filePath = downloadFilePath

  // Write to file path for Smart VDS Report
  doc
    .pipe(fs.createWriteStream(filePath))

  // Create pdf document
  doc
    .font('Times-Roman')
    .fontSize('20')
    .text('Smart VDS Report', {
      align: 'left'
    })
    .fontSize('10')
    .moveDown(2)
    .text(new Date().toLocaleString('en-US'), {
      align: 'left'
    })
    .font('Times-Bold')
    .moveDown(0.5)
    .text(`Number of Vulnerabilities Found: ${totalVulnerabilityCount}`, {
      align: 'left'
    })
    .moveDown(2)
    .fontSize('12')
    .text('Overview', {
      align: 'left'
    })
    .moveDown(1)

  // Generate table for report overview
  const table = {
    title: '',
    fontSize: 10,
    headers: [
      { label: 'Name', property: 'name', width: 200, headerAlign: 'center', renderer: null },
      { label: 'Severity', property: 'severity', width: 90, align: 'center', renderer: null },
      { label: 'Number Found', property: 'count', width: 90, align: 'center', renderer: null }
    ],
    datas: vulnerabilities
  }

  const tableOptions = {
    prepareHeader: () => doc.font('Times-Bold').fontSize(10),
    prepareRow: (row, indexColumn, indexRow, rectRow) => {
      doc.font('Times-Roman').fontSize(10)
      if (indexColumn === 1) {
        if (row.severity === 'LOW') {
          doc
            .font('Times-Bold')
            .fillColor('#fbda19')
        } else if (row.severity === 'MEDIUM') {
          doc
            .font('Times-Bold')
            .fillColor('#ff9600')
        } else if (row.severity === 'HIGH') {
          doc
            .font('Times-Bold')
            .fillColor('#f44336')
        }
      } else {
        doc
          .font('Times-Roman')
          .fillColor('black')
      }
    }
  }

  await doc.table(table, tableOptions, () => {})

  doc
    .moveDown(2)
    .fontSize('12')
    .font('Times-Bold')
    .text('Vulnerabilities Detected', {
      align: 'left'
    })
    .moveDown(0.5)

  vulnerabilities.forEach((vulnerability) => {
    doc
      .fontSize('10')
      .font('Times-Bold')
      .fillColor('black')
      .text(vulnerability.name, {
        underline: true,
        align: 'left'
      })
      .font('Times-Roman')
      .text('Severity Level: ', {
        continued: true
      })

    if (vulnerability.severity === 'LOW') {
      doc
        .font('Times-Bold')
        .fillColor('#fbda19')
        .text(vulnerability.severity, {
          continued: false
        })
    } else if (vulnerability.severity === 'MEDIUM') {
      doc
        .font('Times-Bold')
        .fillColor('#ff9600')
        .text(vulnerability.severity, {
          continued: false
        })
    } else if (vulnerability.severity === 'HIGH') {
      doc
        .font('Times-Bold')
        .fillColor('#f44336')
        .text(vulnerability.severity, {
          continued: false
        })
    }

    if (vulnerability.count === 1) {
      doc
        .font('Times-Roman')
        .fillColor('black')
        .text('Found: ' + vulnerability.count + ' Instance')
    } else {
      doc
        .font('Times-Roman')
        .fillColor('black')
        .text('Found: ' + vulnerability.count + ' Instances')
    }

    let instanceCount = 0
    vulnerability.instances.forEach((instance) => {
      instanceCount += 1
      doc
        .fillColor('black')
        .text('Instance Number ' + instanceCount + ':')
        .fillColor('#3d9edf')
        .text(JSON.stringify(instance))
        .moveDown(0.5)
    })

    doc
      .moveDown(0.5)
      .fillColor('#8585f8')
      .font('Times-Bold')
      .text('Suggested Mitigations:')

    let mitigationCount = 0
    vulnerability.mitigations.forEach((mitigation) => {
      mitigationCount += 1
      doc
        .font('Times-Roman')
        .text(mitigationCount + ': ' + mitigation)
    })
    doc.moveDown(2)
  })

  // Finalize the PDF and save to file path
  doc.end()
}

module.exports = { downloadReport }
