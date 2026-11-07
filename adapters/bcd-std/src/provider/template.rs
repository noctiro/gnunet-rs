//! Original MPL fixed layout; user data is text, never TeX instructions.
use super::{Cause, Limits, RenderRequest};

struct Text {
    text: String,
    maximum: usize,
}
impl Text {
    fn add(&mut self, text: &str) -> Result<(), Cause> {
        let total = self
            .text
            .len()
            .checked_add(text.len())
            .ok_or(Cause::Limit)?;
        if total > self.maximum {
            return Err(Cause::Limit);
        }
        self.text
            .try_reserve_exact(text.len())
            .map_err(|_| Cause::Limit)?;
        if self.text.capacity() > self.maximum {
            return Err(Cause::Limit);
        }
        self.text.push_str(text);
        Ok(())
    }
    fn literal(&mut self, text: &str) -> Result<(), Cause> {
        for c in text.chars() {
            match c {
                '\\' => self.add("\\textbackslash{}")?,
                '{' => self.add("\\{")?,
                '}' => self.add("\\}")?,
                '$' => self.add("\\$")?,
                '%' => self.add("\\%")?,
                '&' => self.add("\\&")?,
                '#' => self.add("\\#")?,
                '_' => self.add("\\_")?,
                '~' => self.add("\\textasciitilde{}")?,
                '^' => self.add("\\textasciicircum{}")?,
                '\r' | '\n' | '\t' => self.add(" ")?,
                c if c.is_control() => return Err(Cause::Input),
                c => self.add(c.encode_utf8(&mut [0; 4]))?,
            }
            if !matches!(c, ' ' | '\r' | '\n' | '\t') {
                // Break only after the complete UTF-8 display character or its
                // complete fixed TeX escape. The raw URI/QR path never uses
                // this renderer. Oversized wrapped text hits the height gate.
                self.add("\\allowbreak{}")?;
            }
        }
        Ok(())
    }
    fn line(&mut self, label: &str, text: &str) -> Result<(), Cause> {
        if text.is_empty() {
            return Ok(());
        }
        self.add("\\noindent\\textbf{")?;
        self.add(label)?;
        self.add("} ")?;
        self.literal(text)?;
        self.add("\\par\n")
    }
}
fn validate(request: &RenderRequest, limits: Limits) -> Result<(), Cause> {
    let mut retained = request
        .uri
        .capacity()
        .checked_add(request.fingerprint.capacity())
        .ok_or(Cause::Limit)?;
    for text in request.fields.iter().chain([&request.fingerprint]) {
        if text.len() > limits.field_bytes {
            return Err(Cause::Limit);
        }
    }
    for text in &request.fields {
        retained = retained.checked_add(text.capacity()).ok_or(Cause::Limit)?;
    }
    if retained > limits.request_bytes || !request.uri.starts_with("gnunet://gns/") {
        return Err(Cause::Input);
    }
    if request.uri.chars().any(char::is_control) {
        return Err(Cause::Input);
    }
    Ok(())
}
/// readline assigns ordinary byte-token catcodes. The file's final sentinel
/// protects original trailing spaces; only that one final token is removed.
/// No URI byte is inserted as executable document source or percent-decoded.
fn qr(text: &mut Text, png: bool) -> Result<(), Cause> {
    text.add("\\newread\\BCDfile\n\\openin\\BCDfile=uri.txt\n\\endlinechar=-1\n\\readline\\BCDfile to\\BCDline\n\\endlinechar=13\n\\closein\\BCDfile\n\\ExplSyntaxOn\n\\tl_new:N \\l_bcd_uri_tl\n\\tl_set:Nx \\l_bcd_uri_tl { \\exp_args:No \\str_range:nnn { \\BCDline } {1} {-2} }\n\\cs_new_protected:Npn \\bcd_qr:n #1 { ")?;
    text.add(if png {
        "\\qrcode[height=100mm,padding,level=Q]{#1}"
    } else {
        "\\qrcode[height=24mm,padding,level=Q]{#1}"
    })?;
    text.add(" }\n\\exp_args:NV \\bcd_qr:n \\l_bcd_uri_tl\n\\ExplSyntaxOff\n")
}
pub(super) fn build(request: &RenderRequest, limits: Limits) -> Result<String, Cause> {
    validate(request, limits)?;
    let mut text = Text {
        text: String::new(),
        maximum: limits.tex_bytes,
    };
    text.add("\\documentclass{article}\n\\usepackage[utf8]{inputenc}\n\\usepackage[T1]{fontenc}\n\\usepackage[final,nolinks,forget]{qrcode}\n\\pagestyle{empty}\n")?;
    if request.png {
        text.add("\\pdfpagewidth=140mm\n\\pdfpageheight=140mm\n\\hoffset=-1in\n\\voffset=-1in\n\\oddsidemargin=5mm\n\\topmargin=5mm\n\\headheight=0pt\n\\headsep=0pt\n\\topskip=0pt\n\\textwidth=130mm\n\\textheight=130mm\n\\parindent=0pt\n\\begin{document}\n")?;
        qr(&mut text, true)?;
    } else {
        // A self-contained 90x55mm card. Full output adds a same-sized back
        // page with every field; neither layout copies the GNU resource design.
        text.add("\\pdfpagewidth=90mm\n\\pdfpageheight=55mm\n\\hoffset=-1in\n\\voffset=-1in\n\\oddsidemargin=3mm\n\\topmargin=3mm\n\\headheight=0pt\n\\headsep=0pt\n\\topskip=0pt\n\\textwidth=84mm\n\\textheight=49mm\n\\parindent=0pt\n\\newsavebox{\\BCDfront}\n\\newsavebox{\\BCDback}\n\\begin{document}\n\\begin{lrbox}{\\BCDfront}\\begin{minipage}[t]{47mm}\\fontsize{7}{8}\\selectfont\\raggedright\n")?;
        let labels = [
            "Prefix:",
            "Name:",
            "Suffix:",
            "Street:",
            "City:",
            "Phone:",
            "Fax:",
            "Email:",
            "Homepage:",
            "Organization:",
            "Department:",
            "Subdepartment:",
            "Job title:",
        ];
        for (index, field) in request.fields.iter().enumerate() {
            if matches!(index, 0 | 1 | 2 | 7 | 8 | 12) {
                text.line(labels[index], field)?;
            }
        }
        if !request.full {
            text.line("GPG:", &request.fingerprint)?;
        }
        text.add("\\end{minipage}\\end{lrbox}\n\\ifdim\\dimexpr\\ht\\BCDfront+\\dp\\BCDfront\\relax>49mm\\errmessage{Business card front does not fit}\\fi\n\\noindent\\usebox{\\BCDfront}\\hfill\\begin{minipage}[t]{32mm}\\vspace{0pt}\n")?;
        qr(&mut text, false)?;
        text.add("\\par\\centering\\fontsize{6}{7}\\selectfont GNS\\end{minipage}\n")?;
        if request.full {
            text.add("\\newpage\n\\begin{lrbox}{\\BCDback}\\begin{minipage}[t]{84mm}\\fontsize{6}{7}\\selectfont\\raggedright\n")?;
            for (index, field) in request.fields.iter().enumerate() {
                text.line(labels[index], field)?;
            }
            text.line("GPG fingerprint:", &request.fingerprint)?;
            text.add("\\end{minipage}\\end{lrbox}\n\\ifdim\\dimexpr\\ht\\BCDback+\\dp\\BCDback\\relax>49mm\\errmessage{Business card back does not fit}\\fi\n\\noindent\\usebox{\\BCDback}\n")?;
        }
    }
    text.add("\\end{document}\n")?;
    Ok(text.text)
}
