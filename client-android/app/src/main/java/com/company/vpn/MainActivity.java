package com.company.vpn;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout root;
    private String username = "";
    private String connectedId = "";
    private String connectingId = "";
    private final String[][] routes = new String[][] {
        {"1", "vvv.network000.com"},
        {"2", "www.baidu.com"}
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        showLogin();
    }

    private void showLogin() {
        root = baseRoot();
        root.addView(label("准备连接", true));
        LinearLayout accountRow = row();
        accountRow.addView(label("账户", false));
        EditText account = input("");
        accountRow.addView(account);
        root.addView(accountRow);

        LinearLayout passwordRow = row();
        passwordRow.addView(label("密码", false));
        EditText password = input("");
        password.setInputType(0x00000081);
        passwordRow.addView(password);
        CheckBox remember = new CheckBox(this);
        remember.setText("保存密码");
        remember.setTextSize(14);
        passwordRow.addView(remember);
        root.addView(passwordRow);

        Button login = button("登录", 178);
        login.setOnClickListener(v -> {
            username = account.getText().toString().trim();
            showRoutes();
        });
        root.addView(login);
        root.addView(version());
        setContentView(root);
    }

    private void showRoutes() {
        root = baseRoot();
        root.addView(label(connectedId.isEmpty() ? "准备连接" : "已连接", true));
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(20, 20, 20, 20);
        panel.setBackgroundColor(Color.WHITE);
        root.addView(panel, new LinearLayout.LayoutParams(-1, -2));
        for (String[] route : routes) {
            panel.addView(routeRow(route[0], route[1]));
        }
        root.addView(version());
        setContentView(root);
    }

    private View routeRow(String id, String host) {
        LinearLayout row = row();
        row.setPadding(14, 8, 14, 8);
        TextView dot = new TextView(this);
        dot.setText("●");
        dot.setTextColor(id.equals(connectedId) ? Color.rgb(25, 150, 76) : Color.rgb(230, 0, 72));
        row.addView(dot);
        LinearLayout names = new LinearLayout(this);
        names.setOrientation(LinearLayout.VERTICAL);
        TextView hostView = text(host, 14, Color.BLACK);
        TextView userView = text(username, 14, Color.rgb(125, 135, 155));
        names.addView(hostView);
        names.addView(userView);
        row.addView(names, new LinearLayout.LayoutParams(0, -2, 1));
        Button action = button(id.equals(connectedId) ? "断开" : (id.equals(connectingId) ? "连接中" : "连接"), 76);
        action.setEnabled(connectedId.isEmpty() || id.equals(connectedId));
        action.setOnClickListener(v -> {
            if (id.equals(connectedId)) {
                connectedId = "";
                showRoutes();
                return;
            }
            connectingId = id;
            showRoutes();
            handler.postDelayed(() -> {
                connectedId = id;
                connectingId = "";
                showRoutes();
            }, 600);
        });
        row.addView(action);
        return row;
    }

    private LinearLayout baseRoot() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        view.setGravity(Gravity.CENTER_HORIZONTAL);
        view.setPadding(36, 24, 36, 14);
        view.setBackgroundColor(Color.rgb(247, 250, 255));
        return view;
    }

    private LinearLayout row() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.HORIZONTAL);
        view.setGravity(Gravity.CENTER_VERTICAL);
        view.setPadding(0, 6, 0, 6);
        return view;
    }

    private TextView label(String value, boolean centered) {
        TextView view = text(value, 14, Color.BLACK);
        view.setGravity(Gravity.CENTER);
        view.setPadding(12, 4, 12, 4);
        view.setBackgroundColor(Color.rgb(235, 240, 250));
        return view;
    }

    private EditText input(String value) {
        EditText view = new EditText(this);
        view.setText(value);
        view.setTextSize(14);
        view.setSingleLine(true);
        view.setTypeface(Typeface.create("serif", Typeface.NORMAL));
        view.setPadding(6, 0, 6, 0);
        view.setMinHeight(24);
        view.setWidth(132);
        return view;
    }

    private Button button(String value, int width) {
        Button view = new Button(this);
        view.setText(value);
        view.setTextSize(14);
        view.setTextColor(Color.WHITE);
        view.setBackgroundColor(Color.rgb(46, 112, 214));
        view.setWidth(width);
        view.setMinHeight(32);
        return view;
    }

    private TextView text(String value, int size, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(Typeface.create("serif", Typeface.NORMAL));
        return view;
    }

    private TextView version() {
        String version = BuildConfig.VERSION_NAME;
        TextView view = text("版本号 " + version, 14, Color.rgb(45, 80, 120));
        view.setPadding(20, 9, 20, 9);
        view.setBackgroundColor(Color.rgb(237, 247, 255));
        return view;
    }
}
