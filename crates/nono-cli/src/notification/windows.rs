//! Windows notification backend using PowerShell WPF dialog.
//!
//! On Windows, CLI tools cannot easily show toast notifications with
//! action buttons (requires an app bundle with AUMID). Instead, we
//! use a PowerShell script to show a WPF dialog with a Deny button,
//! an Approve button, and a ComboBox dropdown for duration selection
//! (Once / Session / Always).
//!
//! This approach:
//! - Works without an app bundle or AUMID registration
//! - Gives a real modal dialog (not a fleeting toast)
//! - Supports timeout by closing the window after N seconds
//! - Returns which button was clicked and the selected duration

use super::{ApprovalDuration, NotificationResult};

/// Show a Windows modal dialog asking the user to approve a network request.
///
/// Uses PowerShell with WPF to display a dialog with a Deny button,
/// an Approve button, and a ComboBox for duration (Once / Session / Always).
///
/// The dialog auto-closes after `timeout_secs` seconds,
/// returning `Dismissed`.
pub fn show_windows_notification(host: &str, timeout_secs: u64) -> NotificationResult {
    let script = format!(
        r#"
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$window = New-Object System.Windows.Window
$window.Title = 'nono: Network access blocked'
$window.SizeToContent = 'WidthAndHeight'
$window.WindowStartupLocation = 'CenterScreen'
$window.ResizeMode = 'NoResize'
$window.Topmost = $true

$stack = New-Object System.Windows.Controls.StackPanel
$stack.Margin = '20'

$text = New-Object System.Windows.Controls.TextBlock
$text.Text = "Host: {host}`nAllow this host to access the network?"
$text.Margin = '0,0,0,15'
$text.FontSize = 14
$stack.Children.Add($text)

$btnPanel = New-Object System.Windows.Controls.StackPanel
$btnPanel.Orientation = 'Horizontal'
$btnPanel.HorizontalAlignment = 'Center'

$script:result = 'Dismissed'

$combo = New-Object System.Windows.Controls.ComboBox
$combo.Width = 100
$combo.Margin = '5,0'
$combo.IsEditable = $false
$combo.IsReadOnly = $true
[void]$combo.Items.Add('Once')
[void]$combo.Items.Add('Session')
[void]$combo.Items.Add('Always')
$combo.SelectedIndex = 1

$btnDeny = New-Object System.Windows.Controls.Button
$btnDeny.Content = 'Deny'
$btnDeny.Margin = '5,0'
$btnDeny.Padding = '10,5'
$btnDeny.Add_Click({{ $dur = $combo.SelectedItem; $script:result = "Deny|$dur"; $window.Close() }})

$btnApprove = New-Object System.Windows.Controls.Button
$btnApprove.Content = 'Approve'
$btnApprove.Margin = '5,0'
$btnApprove.Padding = '10,5'
$btnApprove.IsDefault = $true
$btnApprove.Add_Click({{ $dur = $combo.SelectedItem; $script:result = "Approve|$dur"; $window.Close() }})

$btnPanel.Children.Add($btnDeny)
$btnPanel.Children.Add($combo)
$btnPanel.Children.Add($btnApprove)
$stack.Children.Add($btnPanel)
$window.Content = $stack

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds({timeout_secs})
$timer.Add_Tick({{ $script:result = 'Dismissed'; $window.Close() }})
$timer.Start()

$window.Add_Closing({{ $timer.Stop() }})

$window.ShowDialog() | Out-Null
Write-Output $script:result
"#
    );

    let output = match std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("Failed to run PowerShell for network approval: {e}");
            return NotificationResult::Dismissed;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("PowerShell returned error: {stderr}");
        return NotificationResult::Dismissed;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if let Some(duration_str) = stdout.strip_prefix("Approve|") {
        match duration_str.parse::<ApprovalDuration>() {
            Ok(d) => NotificationResult::Approve(d),
            Err(_) => {
                tracing::warn!("Unknown approval duration in PowerShell response: {stdout}");
                NotificationResult::Dismissed
            }
        }
    } else if let Some(duration_str) = stdout.strip_prefix("Deny|") {
        match duration_str.parse::<ApprovalDuration>() {
            Ok(d) => NotificationResult::Deny(d),
            Err(_) => {
                tracing::warn!("Unknown deny duration in PowerShell response: {stdout}");
                NotificationResult::Dismissed
            }
        }
    } else {
        tracing::warn!("Unknown PowerShell dialog response: {stdout}");
        NotificationResult::Dismissed
    }
}
