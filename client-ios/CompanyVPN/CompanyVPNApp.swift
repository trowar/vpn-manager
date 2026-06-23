import SwiftUI

@main
struct CompanyVPNApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var rememberPassword = false
    @State private var loggedIn = false
    @State private var connectingID = ""
    @State private var connectedID = ""

    private let routes = [
        ("1", "vvv.network000.com"),
        ("2", "www.baidu.com")
    ]

    var body: some View {
        VStack(spacing: 18) {
            if !loggedIn {
                Text("准备连接").labelPill()
                HStack(spacing: 10) {
                    Text("账户").labelPill()
                    TextField("", text: $username).inputBox()
                }
                HStack(spacing: 10) {
                    Text("密码").labelPill()
                    SecureField("", text: $password).inputBox(width: 110)
                    Toggle("保存密码", isOn: $rememberPassword).toggleStyle(.switch).labelsHidden()
                }
                Button("登录") { loggedIn = true }
                    .primaryButton(width: 178)
            } else {
                Text(connectedID.isEmpty ? "准备连接" : "已连接").labelPill()
                VStack(spacing: 14) {
                    ForEach(routes, id: \.0) { route in
                        HStack(spacing: 12) {
                            Circle().fill(connectedID == route.0 ? .green : .red).frame(width: 9, height: 9)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(route.1)
                                Text(username).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(connectedID == route.0 ? "断开" : (connectingID == route.0 ? "连接中" : "连接")) {
                                if connectedID == route.0 {
                                    connectedID = ""
                                } else {
                                    connectingID = route.0
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                                        connectedID = route.0
                                        connectingID = ""
                                    }
                                }
                            }
                            .primaryButton(width: 76)
                            .disabled(!connectedID.isEmpty && connectedID != route.0)
                        }
                        .routeCard()
                    }
                }
                .padding(20)
                .background(.white)
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            Text("版本号 client-dev")
                .monospacedDigit()
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 9)
                .padding(.horizontal, 20)
                .background(Color(red: 0.93, green: 0.97, blue: 1.0))
                .cornerRadius(8)
        }
        .font(.custom("FangSong", size: 14))
        .padding(24)
        .background(Color(red: 0.97, green: 0.98, blue: 1.0))
    }
}

extension View {
    func labelPill() -> some View {
        self.padding(.horizontal, 12).padding(.vertical, 4).background(Color(red: 0.92, green: 0.94, blue: 0.98)).cornerRadius(4)
    }

    func inputBox(width: CGFloat = 120) -> some View {
        self.frame(width: width, height: 24).padding(.horizontal, 6).background(.white).overlay(RoundedRectangle(cornerRadius: 3).stroke(Color.gray.opacity(0.55)))
    }

    func primaryButton(width: CGFloat) -> some View {
        self.frame(width: width, height: 32).background(Color(red: 0.18, green: 0.44, blue: 0.84)).foregroundStyle(.white).cornerRadius(6)
    }

    func routeCard() -> some View {
        self.padding(.horizontal, 14).frame(height: 48).background(Color(red: 0.98, green: 0.99, blue: 1.0)).clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
