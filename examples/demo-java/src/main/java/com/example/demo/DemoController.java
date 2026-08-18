package com.example.demo;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HyqSast 演示项目 —— 精心挑选的 4 个典型漏洞 + 1 个安全样例。
 *
 * 目的：现场演示「源 → 链 → 汇」三步，覆盖不同漏洞类别与不同传播形态：
 *   ① SQL 注入     —— 跨 3 个函数的完整传播链（最长的一条链）
 *   ② 命令注入     —— 单层透传
 *   ③ 路径穿越     —— 拼接后进入文件系统
 *   ④ XSS（已净化）—— 展示 sanitizer 生效，标注 sanitized=True
 *   ⑤ 安全样例     —— 参数化查询，应当不产生 finding（不冤枉好人）
 */
@RestController
public class DemoController {

    private Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "pw");

    // ──── ① SQL 注入：跨 3 个函数的传播链（source → 拼接 → 透传 → sink）────
    @GetMapping("/users")
    public String users(@RequestParam String id) throws Exception {
        // 链: users -> queryUser -> execute -> executeQuery  ← SINK
        return queryUser(id);
    }

    private String queryUser(String id) throws Exception {
        String sql = "SELECT * FROM users WHERE id = " + id;   // 污点在此拼接进 SQL
        return execute(sql);
    }

    private String execute(String sql) throws Exception {
        Statement st = conn.createStatement();
        st.executeQuery(sql);                                  // ← SINK: sql_injection
        return sql;
    }

    // ──── ② 命令注入：单层透传 ────
    @GetMapping("/run")
    public String run(@RequestParam String cmd) throws Exception {
        return exec(cmd);
    }

    private String exec(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);            // ← SINK: command_injection
        p.waitFor();
        return cmd;
    }

    // ──── ③ 路径穿越：拼接后进入文件系统 ────
    @GetMapping("/download")
    public String download(@RequestParam String filename) throws Exception {
        return readFile(filename);
    }

    private String readFile(String filename) throws Exception {
        FileInputStream in = new FileInputStream("/data/" + filename);  // ← SINK: path_traversal
        byte[] bytes = in.readAllBytes();
        in.close();
        return new String(bytes);
    }

    // ──── ④ XSS：escapeHtml4 净化后输出 —— 应标注 sanitized=True，仍上报供复核 ────
    @GetMapping("/profile")
    public void profile(@RequestParam String bio, HttpServletResponse resp) throws Exception {
        String escaped = StringEscapeUtils.escapeHtml4(bio);   // sanitizer: xss
        resp.getWriter().write(escaped);                       // ← SINK: xss（已净化）
    }

    // ──── ⑤ 安全样例：参数化查询，用户输入只进 setString，不拼进 SQL ────
    @GetMapping("/items")
    public String items(@RequestParam String q) throws Exception {
        java.sql.PreparedStatement ps =
                conn.prepareStatement("SELECT * FROM items WHERE name = ?");
        ps.setString(1, q);                                    // sanitizer: sql_injection
        ps.executeQuery();                                     // 无污点到达，不报
        return "ok";
    }

    // 仅供演示：供 ② 引用，避免编译器优化掉（不影响分析）
    public static void main(String[] args) throws Exception {
        System.out.println(new DemoController().users("1"));
    }
}
