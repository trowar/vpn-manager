import CompanyVPNShared
import SwiftUI

@main
struct CompanyVPNMacApp: App {
    @StateObject private var model = CompanyVPNViewModel()

    var body: some Scene {
        WindowGroup("Company VPN") {
            CompanyVPNRootView()
                .environmentObject(model)
                .frame(width: 430)
                .fixedSize(horizontal: false, vertical: true)
        }
        .windowResizability(.contentSize)
    }
}

struct CompanyVPNRootView: View {
    @EnvironmentObject private var model: CompanyVPNViewModel

    var body: some View {
        VStack(spacing: 18) {
            if model.routes.isEmpty {
                LoginView()
            } else {
                RouteListView()
            }
            VersionBar(version: model.config.version)
        }
        .padding(.horizontal, 36)
        .padding(.top, 18)
        .padding(.bottom, 10)
        .background(Color(red: 0.97, green: 0.98, blue: 1.0))
        .font(.custom("FangSong", size: 14))
    }
}

struct LoginView: View {
    @EnvironmentObject private var model: CompanyVPNViewModel

    var body: some View {
        VStack(spacing: 16) {
            Text("准备连接")
                .labelPill()

            VStack(spacing: 12) {
                HStack(spacing: 10) {
                    Text("账户").labelPill()
                    TextField("", text: $model.username)
                        .textFieldStyle(.plain)
                        .inputBox()
                }
                HStack(spacing: 10) {
                    Text("密码").labelPill()
                    SecureField("", text: $model.password)
                        .textFieldStyle(.plain)
                        .inputBox(width: 120)
                    Toggle("保存密码", isOn: $model.rememberPassword)
                        .toggleStyle(.checkbox)
                        .fixedSize()
                }
                Button("登录") {
                    Task { await model.login() }
                }
                .primaryButton(width: 178)
                if !model.message.isEmpty {
                    Text(model.message)
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
}

struct RouteListView: View {
    @EnvironmentObject private var model: CompanyVPNViewModel

    var body: some View {
        VStack(spacing: 14) {
            Text(model.connectionState.title)
                .labelPill()
                .padding(.bottom, 2)

            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 16) {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Color(red: 0.28, green: 0.34, blue: 0.51))
                        .frame(width: 56, height: 56)
                        .overlay(Text("\(model.routes.count)").font(.system(size: 28, weight: .bold)).foregroundColor(.white))
                    VStack(alignment: .leading, spacing: 6) {
                        Text("可用服务器").foregroundColor(.secondary)
                        Text("\(model.routes.count) 条线路")
                            .font(.custom("FangSong", size: 18))
                    }
                }

                ForEach(model.routes) { route in
                    HStack(spacing: 12) {
                        Circle()
                            .fill(model.isRouteActive(route) ? Color.green : Color.red)
                            .frame(width: 9, height: 9)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(route.displayHost)
                                .font(.custom("FangSong", size: 14))
                            Text(route.account)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button(model.buttonTitle(for: route)) {
                            Task {
                                if model.isRouteActive(route) {
                                    await model.disconnect()
                                } else {
                                    await model.connect(route)
                                }
                            }
                        }
                        .primaryButton(width: 76)
                        .disabled(model.isButtonDisabled(for: route))
                    }
                    .routeCard()
                }
            }
            .padding(20)
            .background(.white)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 0.82, green: 0.87, blue: 0.94)))

            HStack(spacing: 35) {
                TrafficBox(title: "接收", value: model.traffic.rxText, color: Color(red: 0.91, green: 0.96, blue: 1.0))
                TrafficBox(title: "发送", value: model.traffic.txText, color: Color(red: 0.90, green: 1.0, blue: 0.96))
            }
        }
    }
}

struct TrafficBox: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).foregroundColor(.secondary)
            Text(value).font(.custom("FangSong", size: 14))
        }
        .frame(width: 130, height: 48, alignment: .leading)
        .padding(.leading, 20)
        .background(color)
        .cornerRadius(8)
    }
}

struct VersionBar: View {
    let version: String

    var body: some View {
        Text("版本号 \(version)")
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 9)
            .padding(.horizontal, 20)
            .background(Color(red: 0.93, green: 0.97, blue: 1.0))
            .cornerRadius(8)
            .monospacedDigit()
    }
}

extension View {
    func labelPill() -> some View {
        self
            .font(.custom("FangSong", size: 14))
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
            .background(Color(red: 0.92, green: 0.94, blue: 0.98))
            .cornerRadius(4)
    }

    func inputBox(width: CGFloat = 120) -> some View {
        self
            .font(.custom("FangSong", size: 14))
            .frame(width: width, height: 24)
            .padding(.horizontal, 6)
            .background(Color.white)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(Color(red: 0.66, green: 0.70, blue: 0.78)))
    }

    func primaryButton(width: CGFloat) -> some View {
        self
            .font(.custom("FangSong", size: 14))
            .frame(width: width, height: 32)
            .background(Color(red: 0.18, green: 0.44, blue: 0.84))
            .foregroundColor(.white)
            .cornerRadius(6)
    }

    func routeCard() -> some View {
        self
            .padding(.horizontal, 14)
            .frame(height: 48)
            .background(Color(red: 0.98, green: 0.99, blue: 1.0))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(red: 0.90, green: 0.94, blue: 0.98)))
            .cornerRadius(8)
    }
}
