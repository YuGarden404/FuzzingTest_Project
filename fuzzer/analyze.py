import pandas as pd
import matplotlib.pyplot as plt
import os
import glob


def generate_multi_target_report():
    out_dir = "./out"
    # 获取目录下所有 stats_*.csv 文件
    csv_files = glob.glob(os.path.join(out_dir, "stats_target*.csv"))

    if not csv_files:
        print(f"错误：在 {out_dir} 中找不到任何 stats_target*.csv 文件！")
        return

    plt.figure(figsize=(12, 7))

    summary_data = []

    # 循环读取每个目标的数据并绘图
    for csv_file in sorted(csv_files):
        target_name = os.path.basename(csv_file).replace("stats_", "").replace(".csv", "")
        df = pd.read_csv(csv_file)

        if df.empty:
            continue

        # 绘制曲线
        plt.plot(df['time'], df['cov'], label=target_name, linewidth=1.5)

        # 收集汇总信息
        summary_data.append({
            "Target": target_name,
            "Max Coverage": df['cov'].max(),
            "Total Time": df['time'].max()
        })

    # 图表美化
    plt.title('Multi-Target Fuzzing Coverage Comparison', fontsize=16)
    plt.xlabel('Time (seconds)', fontsize=12)
    plt.ylabel('Edges Discovered', fontsize=12)
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))  # 标签放在图外
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()

    # 保存对比图
    plot_path = os.path.join(out_dir, "multi_target_comparison.png")
    plt.savefig(plot_path)
    print(f"[+] 10条曲线对比图已生成: {plot_path}")

    # 生成 Markdown 报告
    report_path = os.path.join(out_dir, "experiment_report.md")
    with open(report_path, "w") as f:
        f.write("# Fuzzing 实验多目标测试报告\n\n")
        f.write("## 1. 测试汇总表格\n\n")
        f.write("| 目标名称 | 最终覆盖边数 | 测试耗时 (s) |\n")
        f.write("| :--- | :--- | :--- |\n")
        for item in summary_data:
            f.write(f"| {item['Target']} | {item['Max Coverage']} | {item['Total Time']:.2f} |\n")

        f.write("\n\n## 2. 覆盖率增长对比图\n\n")
        f.write("![Coverage Comparison](multi_target_comparison.png)\n")

    print(f"[+] 实验汇总报告已生成: {report_path}")


if __name__ == "__main__":
    generate_multi_target_report()