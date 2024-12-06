# **Log Analysis Project**

This project analyzes server log files to extract and report key information, focusing on cybersecurity use cases. 

---

### **Features**
1. **Analyze Requests Per IP**:
   - Count the number of requests made by each IP.
   - Display the sorted results.

2. **Find the Most Accessed Endpoint**:
   - Identify the most frequently accessed endpoint in the logs.

3. **Detect Suspicious Activity**:
   - Highlight IPs with failed login attempts exceeding a configurable threshold.

4. **Save Analysis to a CSV File**:
   - Results are saved to `log_analysis_results.csv` in an organized format.

---

### **File Structure**
log_analysis_project/ ├── sample.log # Log file with sample data ├── log_analysis.py # Python script to analyze logs ├── log_analysis_results.csv # Generated CSV file


---

### **Prerequisites**
- **Python**: Version 3.8 or higher.

---

### **How to Run the Project**
**Clone the Repository**:
   ```bash
   git clone <https://github.com/GudavalliSudhakar/log_analysis_project.git>
   cd log_analysis_project
