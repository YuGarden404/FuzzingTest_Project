import pandas as pd
import matplotlib.pyplot as plt
import os
import glob

MAP_SIZE = 65536

def generate_multi_target_report():
    out_dir = "./out"
    csv_files = glob.glob(os.path.join(out_dir, "stats_target*.csv"))

    if not csv_files:
        print(f"错误：在 {out_dir} 中找不到任何 stats_target*.csv 文件！")
        return

    # 1. 收集数据
    all_data = {}
    summary_data = []
    
    for csv_file in sorted(csv_files):
        target_name = os.path.basename(csv_file).replace("stats_", "").replace(".csv", "")
        try:
            df = pd.read_csv(csv_file)
            if not df.empty:
                all_data[target_name] = df
                summary_data.append({
                    "Target": target_name,
                    "Max Coverage": df['cov'].max(),
                    "Total Time": df['time'].max()
                })
        except Exception as e:
            print(f"[-] Error reading {csv_file}: {e}")

    if not all_data:
        print("[-] No valid data found to plot.")
        return

    # 2. 绘制图表 1: 绝对覆盖率 (Edges)
    plt.figure(figsize=(12, 7))
    for target_name, df in all_data.items():
        plt.plot(df['time'], df['cov'], label=target_name, linewidth=1.5)

    plt.title('Multi-Target Fuzzing Coverage Comparison (Edges)', fontsize=16)
    plt.xlabel('Time (seconds)', fontsize=12)
    plt.ylabel('Edges Discovered', fontsize=12)
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    
    plot_path_edges = os.path.join(out_dir, "multi_target_comparison.png")
    plt.savefig(plot_path_edges)
    plt.close() # 关闭画布，防止重叠
    print(f"[+] 绝对覆盖率图已生成: {plot_path_edges}")

    # 3. 绘制图表 2: 覆盖率百分比 (%)
    plt.figure(figsize=(12, 7))
    for target_name, df in all_data.items():
        # 计算百分比
        cov_pct = (df['cov'] / MAP_SIZE) * 100
        plt.plot(df['time'], cov_pct, label=target_name, linewidth=1.5)

    plt.title('Multi-Target Fuzzing Coverage Percentage (%)', fontsize=16)
    plt.xlabel('Time (seconds)', fontsize=12)
    plt.ylabel('Map Coverage (%)', fontsize=12)
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()

    plot_path_pct = os.path.join(out_dir, "multi_target_comparison_pct.png")
    plt.savefig(plot_path_pct)
    plt.close()
    print(f"[+] 覆盖率百分比图已生成: {plot_path_pct}")

    # 4. 生成 Markdown 报告
    report_path = os.path.join(out_dir, "experiment_report.md")
    with open(report_path, "w") as f:
        f.write("# Fuzzing 实验多目标测试报告\n\n")
        f.write("## 1. 测试汇总表格\n\n")
        f.write("| 目标名称 | 最终覆盖边数 | 覆盖率 (%) | 测试耗时 (s) |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for item in summary_data:
            cov_pct = (item['Max Coverage'] / MAP_SIZE) * 100
            f.write(f"| {item['Target']} | {item['Max Coverage']} | {cov_pct:.4f}% | {item['Total Time']:.2f} |\n")

        f.write("\n\n## 2. 覆盖率增长趋势 (绝对值)\n\n")
        f.write("![Coverage Edges](multi_target_comparison.png)\n")
        
        f.write("\n\n## 3. 覆盖率增长趋势 (百分比)\n\n")
        f.write("![Coverage Percentage](multi_target_comparison_pct.png)\n")

    print(f"[+] 实验汇总报告已生成: {report_path}")


if __name__ == "__main__":
    generate_multi_target_report()