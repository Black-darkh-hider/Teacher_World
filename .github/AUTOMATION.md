# GitHub Automation Setup

This repository has been configured with comprehensive GitHub automation to streamline development, security, and maintenance processes.

## 🚀 Automated Workflows

### 1. CI/CD Pipeline (`ci.yml`)
**Triggers:** Push to main/develop, Pull Requests
- **Multi-Node Testing:** Tests across Node.js versions 16.x, 18.x, and 20.x
- **Security Auditing:** Runs `npm audit` to check for vulnerabilities
- **Code Linting:** Attempts to run ESLint if configured
- **Build Verification:** Runs build scripts if available
- **Artifact Archiving:** Saves build artifacts for deployment

### 2. Security Scanning (`security.yml`)
**Triggers:** Push, PR, Weekly schedule (Mondays 9 AM UTC)
- **Vulnerability Scanning:** Automated npm audit with auto-fix attempts
- **CodeQL Analysis:** GitHub's semantic code analysis for security issues
- **Dependency Review:** Reviews new dependencies in PRs for security risks
- **Automated Fixes:** Attempts to auto-fix security vulnerabilities

### 3. Dependency Management (`dependabot.yml`)
**Schedule:** Weekly (Mondays 9 AM UTC)
- **NPM Dependencies:** Monitors backend package.json for updates
- **GitHub Actions:** Keeps workflow actions up to date
- **Smart Grouping:** Groups patch and minor updates for easier review
- **Auto-labeling:** Adds appropriate labels to dependency PRs

### 4. Auto-Merge (`auto-merge.yml`)
**Triggers:** Dependabot PRs
- **Safe Auto-Merge:** Automatically merges patch and minor dependency updates
- **CI Verification:** Waits for CI tests to pass before merging
- **Manual Review for Major:** Flags major updates for manual review
- **Smart Notifications:** Comments on PRs requiring attention

### 5. Release Automation (`release.yml`)
**Triggers:** Git tags (v*), Manual workflow dispatch
- **Automated Releases:** Creates GitHub releases with changelogs
- **Build Verification:** Ensures tests pass before release
- **Release Archives:** Creates downloadable release packages
- **Changelog Generation:** Automatically generates release notes

### 6. Issue & PR Management (`issue-management.yml`)
**Triggers:** New issues/PRs, Daily schedule
- **Auto-Labeling:** Automatically labels issues and PRs based on content
- **Size Labeling:** Labels PRs by size (XS, S, M, L, XL)
- **Welcome Messages:** Greets new contributors
- **Stale Management:** Manages inactive issues and PRs
- **Smart Categorization:** Labels based on changed files

## 🏷️ Automated Labels

The automation system uses these labels:

### Issue Labels
- `bug` - Bug reports
- `enhancement` - Feature requests
- `needs-triage` - Requires initial review
- `stale` - Inactive for 30+ days

### PR Labels
- `dependencies` - Dependency updates
- `automated` - Automated PRs
- `backend` - Backend changes
- `frontend` - Frontend changes
- `github-actions` - Workflow changes
- `documentation` - Documentation updates
- `size/XS` to `size/XL` - PR size indicators

## 🔧 Configuration

### Dependabot Settings
- **Update Schedule:** Weekly on Mondays
- **Auto-merge:** Enabled for patch/minor updates
- **Review Assignment:** Assigns to repository owner
- **Commit Prefixes:** Uses conventional commit format

### Security Settings
- **Audit Level:** High for blocking, moderate for reporting
- **Auto-fix:** Enabled with force flag for automated fixes
- **CodeQL:** Enabled for JavaScript/TypeScript analysis

### Stale Management
- **Stale After:** 30 days of inactivity
- **Close After:** 7 days of being marked stale
- **Exemptions:** Pinned, security, and enhancement issues

## 🎯 Benefits

### For Developers
- **Reduced Manual Work:** Automated dependency updates and security fixes
- **Consistent Quality:** Automated testing and code analysis
- **Better Organization:** Auto-labeling and categorization
- **Faster Reviews:** Size-based PR labeling and automated checks

### For Security
- **Proactive Monitoring:** Weekly security scans and dependency reviews
- **Automated Fixes:** Auto-application of security patches
- **Vulnerability Tracking:** CodeQL integration for advanced threat detection

### for Maintenance
- **Dependency Freshness:** Regular updates keep dependencies current
- **Issue Hygiene:** Stale issue management keeps the backlog clean
- **Release Automation:** Streamlined release process with changelogs

## 🚦 Getting Started

1. **Enable Branch Protection:** Set up branch protection rules for main/develop
2. **Configure Secrets:** Ensure GITHUB_TOKEN has appropriate permissions
3. **Review Settings:** Adjust automation settings in workflow files as needed
4. **Monitor Activity:** Check the Actions tab to see automation in action

## 📝 Customization

To customize the automation:

1. **Modify Schedules:** Edit cron expressions in workflow files
2. **Adjust Labels:** Update label names and colors in workflow scripts
3. **Change Thresholds:** Modify stale timeouts, PR size limits, etc.
4. **Add Integrations:** Extend workflows with additional actions

## 🆘 Troubleshooting

### Common Issues
- **Failed Auto-merge:** Check if branch protection requires reviews
- **Missing Labels:** Ensure repository has the required labels created
- **Security Scan Failures:** Review npm audit output for manual fixes needed

### Support
- Check workflow run logs in the Actions tab
- Review individual workflow files for configuration details
- Consult GitHub Actions documentation for advanced customization

---

*This automation setup provides a robust foundation for maintaining code quality, security, and project organization with minimal manual intervention.*