import io
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from backend.extensions import db
from backend.models import AuditLog, SystemLog

def log_audit(action, user_id=None, ip_address=None, details=None):
    """Utility to commit an audit event logs to the database."""
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            details=details,
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        log_system('ERROR', f"Audit logger failed to write to DB: {e}")

def log_system(level, message):
    """Utility to write diagnostic messages to system logs database."""
    try:
        # Standard console print
        print(f"[{datetime.utcnow().isoformat()}] [{level}] {message}")
        log = SystemLog(
            level=level.upper(),
            message=message,
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"System logger critical error: {e}")

def generate_csv_report(headers, data):
    """
    Generates a CSV string buffer.
    
    Parameters:
    - headers (list of str): column headers
    - data (list of list/dict): data rows matching headers keying order
    """
    output = io.StringIO()
    writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)
    for row in data:
        writer.writerow(row)
    return output.getvalue()

def generate_pdf_report(title, headers, data):
    """
    Generates a binary PDF buffer using reportlab.
    
    Parameters:
    - title (str)
    - headers (list of str)
    - data (list of list of str)
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []
    
    # Custom Styles for dark cyberpunk/professional appearance
    styles = getSampleStyleSheet()
    
    # Add custom Title Style
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'), # dark slate
        spaceAfter=15
    )
    
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748B'), # grey
        spaceAfter=25
    )
    
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1E293B')
    )
    
    header_style = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    # Document Header
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(f"Exported: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Network Monitoring Division", meta_style))
    story.append(Spacer(1, 10))
    
    # Transform strings to Paragraph objects to support auto wrapping in cells
    formatted_headers = [Paragraph(h, header_style) for h in headers]
    formatted_rows = []
    for row in data:
        formatted_rows.append([Paragraph(str(cell), cell_style) for cell in row])
        
    table_data = [formatted_headers] + formatted_rows
    
    # Calculate explicit widths dynamically or statically (using remaining width)
    # Page width is 612 (letter width). Margins take 72. Printable area = 540.
    col_count = len(headers)
    col_width = 540.0 / col_count
    
    report_table = Table(table_data, colWidths=[col_width]*col_count)
    
    # Styled like a professional security audit log
    t_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')), # Dark primary
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('TOPPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')), # grid lines
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]), # alternating rows
        ('TOPPADDING', (0,1), (-1,-1), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 6),
    ])
    report_table.setStyle(t_style)
    story.append(report_table)
    
    doc.build(story)
    pdf_val = buffer.getvalue()
    buffer.close()
    return pdf_val
