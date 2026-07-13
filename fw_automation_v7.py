import os
import sys
import json
import time
import re
import ipaddress
from datetime import datetime
import customtkinter as ctk
import tkinter.messagebox as messagebox
from playwright.sync_api import sync_playwright

# =============================================================================
# 1. 파일 데이터 로드 (장비 정보 & 예외 IP)
# =============================================================================
def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def load_devices_data():
    json_path = os.path.join(get_base_dir(), "devices.json")
    if not os.path.exists(json_path):
        messagebox.showerror("오류", f"'devices.json' 파일이 없습니다.\n경로: {json_path}")
        sys.exit()
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_whitelist():
    txt_path = os.path.join(get_base_dir(), "whitelist.txt")
    if not os.path.exists(txt_path):
        return []
    with open(txt_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def save_whitelist(ip_list):
    txt_path = os.path.join(get_base_dir(), "whitelist.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# 차단 예외 IP 목록 (단일 IP 또는 1.1.1.0/24 형태의 서브넷 입력)\n")
        for ip in ip_list:
            f.write(ip + "\n")

def is_ip_whitelisted(target_ip, whitelist):
    """
    target_ip(단일 IP 또는 서브넷)가 예외 목록과 하나라도 겹치면 True.
    - 단일 IP 차단 시: 예외 목록의 서브넷에 포함되거나, 동일 IP가 있으면 예외 처리
    - 서브넷 차단 시: 예외 목록의 서브넷과 대역이 겹치거나(overlap),
      예외로 등록된 단일 IP가 그 대역 안에 포함되어 있어도 예외 처리
      (예: 1.1.1.0/24를 차단하려는데 1.1.1.5가 예외 목록에 있으면 차단 불가)
    """
    try:
        if "/" in target_ip:
            target = ipaddress.IPv4Network(target_ip, strict=False)
        else:
            target = ipaddress.IPv4Address(target_ip)
    except ValueError:
        return False  # 잘못된 입력은 메인에서 걸러짐

    for w_ip in whitelist:
        try:
            w_net = ipaddress.IPv4Network(w_ip, strict=False) if "/" in w_ip else ipaddress.IPv4Address(w_ip)
        except ValueError:
            continue

        if isinstance(target, ipaddress.IPv4Address):
            if isinstance(w_net, ipaddress.IPv4Network):
                if target in w_net:
                    return True
            else:
                if target == w_net:
                    return True
        else:  # target이 서브넷인 경우
            if isinstance(w_net, ipaddress.IPv4Network):
                if target.overlaps(w_net):
                    return True
            else:
                if w_net in target:
                    return True
    return False

# =============================================================================
# 2. 방화벽 자동화 봇 구조화
# =============================================================================
class BaseFirewallBot:
    """모든 방화벽 자동화 봇이 상속하는 공통 베이스 클래스"""
    def __init__(self, device, target_ip, country_code=None, case_id=None):
        self.device = device
        self.target_ip = target_ip
        self.country_code = country_code
        self.case_id = case_id
        self.today_str = datetime.now().strftime("%Y%m%d")

    def run(self, logger):
        raise NotImplementedError("하위 클래스에서 run()을 구현해야 합니다.")


class TrusGuardWebBot(BaseFirewallBot):
    def __init__(self, device, target_ip, country_code=None, case_id=None):
        super().__init__(device, target_ip, country_code, case_id)
        self.base_url = f"https://{self.device['ip']}:{self.device['port']}"
        self._prepare_data()

    def _prepare_data(self):
        if self.device.get("format_type", 1) == 1:
            self.obj_name = f"{self.country_code}_{self.target_ip}"
            self.obj_desc = f"{self.today_str}_ES_{self.case_id}"
        else:
            self.obj_name = f"{self.today_str}_ATK_{self.target_ip}"
            self.obj_desc = ""

    def _find_exact_row(self, page, name):
        """현재 로드된 목록 페이지에서 이름이 name과 '정확히' 일치하는 행(tr) 로케이터를 반환합니다."""
        return page.locator("tr", has=page.get_by_text(name, exact=True))

    def _confirm_object_created(self, page, logger):
        """
        객체 저장 버튼을 클릭한 뒤, '이미 등록된 객체' 에러 팝업이 없었다고 해서
        무조건 저장이 성공했다고 가정하지 않는다. (입력값 검증 실패, 세션 만료 등
        다른 사유로 조용히 실패할 수 있음) 반드시 목록을 재조회해서 실제로
        obj_name이 존재하는지 직접 확인한다.
        """
        page.evaluate(f"window.location.replace('{self.base_url}/object/address/ipv4')")
        page.wait_for_selector("input#queryString", timeout=5000)
        page.fill("input#queryString", self.target_ip)
        page.press("input#queryString", "Enter")
        time.sleep(1)

        row = self._find_exact_row(page, self.obj_name)
        if row.count() == 0:
            raise Exception(
                f"'{self.obj_name}' 객체 생성 확인에 실패했습니다. 저장 후 목록에서 조회되지 않습니다. "
                f"입력값 오류, 권한 부족, 세션 만료 등의 사유일 수 있으니 장비에서 직접 확인해주세요."
            )
        logger(f"✅ '{self.obj_name}' 객체가 목록에 정상 생성된 것을 확인했습니다.")

    def get_reference_count(self, page, target_ip):
        """
        IPv4 목록 페이지에서 self.obj_name과 '이름이 정확히 일치하는 행'의 참조수만 읽어옵니다.
        IP로 검색하면 0.0.0.0/0('all') 처럼 해당 IP를 포함하는 다른 상위 대역 객체까지
        함께 검색 결과에 나오기 때문에, 단순히 페이지에서 첫 번째로 찾은 참조수를
        가져오면 엉뚱한(훨씬 큰) 값을 읽어오게 됩니다. 반드시 이름이 obj_name과
        정확히 일치하는 행으로 한정해서 읽어야 합니다.
        """
        page.evaluate(f"window.location.replace('{self.base_url}/object/address/ipv4')")
        page.wait_for_selector("input#queryString", timeout=5000)
        page.fill("input#queryString", target_ip)
        page.press("input#queryString", "Enter")
        time.sleep(1)

        # 이름이 obj_name과 정확히 일치하는 행(tr)만 선택
        target_row = self._find_exact_row(page, self.obj_name)

        if target_row.count() == 0:
            # 이름이 정확히 일치하는 행을 못 찾으면, 잘못된 값(예: 0)으로 진행하지 않고
            # 명확히 실패시켜 수동 확인을 유도한다.
            raise Exception(
                f"참조수 조회 중 '{self.obj_name}' 객체를 검색 결과에서 정확히 찾지 못했습니다. 수동 확인이 필요합니다."
            )

        ref_span = target_row.first.locator("span[reftarget='addr']")
        if ref_span.count() == 0:
            return 0
        try:
            return int(ref_span.first.inner_text().strip())
        except:
            return 0

    def _click_apply_and_confirm(self, page, logger):
        """
        적용 버튼과 확인 팝업을 안정적으로 처리하는 공통 로직.
        (초창기 검증된 버전의 구체적인 XPath 셀렉터와 타이밍을 복원)
        """
        try:
            page.wait_for_selector("div.buttonApply", timeout=5000)
            page.click("div.buttonApply")

            # 범용 'button:has-text' 대신, 초창기에 검증된 정확한 확인 팝업 셀렉터 사용
            confirm_btn_xpath = "//div[contains(@class, 'applyConfirmDialog')]//div[@class='ui-dialog-buttonset']//button[contains(., '확인')]"
            page.wait_for_selector(confirm_btn_xpath, timeout=3000)
            page.click(confirm_btn_xpath)
            logger("[로그] 적용(Apply) 승인 완료")

            # 💡 장비가 게이지바를 띄우고 내부 프로세스를 시작할 최소 정적 마진 확보 (초창기 핵심 보정)
            time.sleep(2.0)
        except Exception:
            logger("[경고] 확인 팝업을 찾지 못함. (무시하고 진행)")

        # 게이지바 대기 (최대 60초, 못 찾으면 안전하게 10초 추가 대기)
        try:
            page.wait_for_selector("#globalProgress", state="hidden", timeout=60000)
        except:
            logger("[경고] 게이지바 감시 타임아웃 -> 안전을 위해 10초 추가 대기")
            time.sleep(10.0)

        # 장비 데이터베이스 반영 안정화를 위한 최종 대기
        time.sleep(1.5)

    def run(self, logger):
        logger(f"▶ [{self.device['name']}] 트러스가드 자동화 시작")
        logger(f"[로그] 객체명: {self.obj_name}")

        with sync_playwright() as p:
            browser = None
            context = None
            page = None
            try:
                browser = p.chromium.launch(
    		headless=False,
    		args=[
        		"--ignore-certificate-errors",
		        "--disable-gpu",                    # GPU 초기화 지연 방지
    		    "--disable-software-rasterizer",
   		     "--no-proxy-server",                # WPAD 자동감지 비활성화
  		      "--proxy-bypass-list=*",
  		      "--disable-background-networking",  # 업데이트/원격설정 체크 비활성화
  		      "--disable-component-update",
  		      "--disable-sync",
 		       "--disable-default-apps",
 		       "--disable-extensions",
		        "--no-first-run",
  		      "--no-default-browser-check",
  		      "--metrics-recording-only",
  		      "--mute-audio",
 		   ],
		)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(10000)  # 기본 대기시간 10초로 최적화
            except Exception as e:
                raise Exception(f"브라우저 기동 실패: {str(e)}")

            try:
                # [Step 0] 빠른 로그인 (domcontentloaded 적용)
                # 최초 접속은 VPN/장비 응답 지연을 감안해 타임아웃을 30초로 넉넉하게 부여
                logger(f"[로그] 장비 접근 중... ({self.device['ip']})")
                try:
                    page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    raise Exception(
                        f"장비({self.device['ip']}:{self.device['port']})에 30초 내 접속하지 못했습니다. "
                        f"VPN 연결 상태 및 장비 응답을 확인해주세요."
                    )
                page.fill("#userId", self.device["id"])
                page.fill("#password", self.device["password"])
                page.click("div.loginButton")

                # 대시보드 메인 진입을 명시적으로 확인 후 세션 안정화 대기 (초창기 검증된 방식)
                try:
                    page.wait_for_url(f"{self.base_url}/main/dashboard/main", timeout=5000)
                    time.sleep(0.5)
                except Exception:
                    logger("[경고] 대시보드 진입 확인 타임아웃 (계속 진행)")
                    time.sleep(1)

                # [Step 1] 객체 추가 (기등록 스킵 로직 포함)
                logger("[로그] 신규 객체 추가 시도")
                # 💡 로그인 이후에는 page.goto()로 강제 새로고침하지 않고,
                # SPA 내부 라우팅(window.location.replace)으로 이동해야 세션/앱 상태가 안전하게 유지된다.
                page.evaluate(f"window.location.replace('{self.base_url}/object/address/ipv4/add')")
                page.wait_for_selector("#name", timeout=5000)
                page.fill("#name", self.obj_name)
                page.fill("#ip", self.target_ip)
                if self.obj_desc:
                    page.fill("#desc", self.obj_desc)
                page.click("div.btnNormal.save")

                # 기등록 객체 여부 확인
                already_exists = False
                try:
                    page.wait_for_selector("//div[contains(text(), '이미 등록된 주소 객체입니다')]", timeout=2000)
                    already_exists = True
                except:
                    pass

                if already_exists:
                    # 이미 등록된 객체라면 참조수를 확인해서 다른 곳에서 쓰이고 있는지 검증
                    logger(f"⚠️ [알림] '{self.obj_name}'은(는) 이미 등록된 객체입니다. 참조수 확인 중...")
                    ref_cnt = self.get_reference_count(page, self.target_ip)
                    if ref_cnt >= 1:
                        raise Exception(
                            f"'{self.obj_name}'은(는) 이미 다른 곳에서 사용 중입니다(참조수: {ref_cnt}). 수동 확인이 필요합니다."
                        )
                    else:
                        logger(f"✅ 참조수 {ref_cnt}, 미사용 객체로 판단 → 객체 생성을 스킵하고 그룹 추가 단계로 이동합니다.")
                else:
                    # '이미 등록된 객체' 에러가 안 떴다고 해서 저장이 성공했다고 가정하지 않고,
                    # 목록을 재조회해서 실제로 생성됐는지 직접 확인한다. 실패 시 즉시 예외로 중단.
                    logger("[로그] 저장 요청 완료 -> 실제 생성 여부 확인 중...")
                    self._confirm_object_created(page, logger)
                    logger("[로그] 객체 생성 확인 완료 -> 장비 적용 중...")
                    self._click_apply_and_confirm(page, logger)

                # [Step 2] 가변 그룹 탐색
                logger(f"[로그] 가변 그룹 추적 (기준: {self.device['group_name']})")
                match = re.match(r"(.+_)(\d+)$", self.device['group_name'])
                if match:
                    group_prefix = match.group(1)
                    page.evaluate(f"window.location.replace('{self.base_url}/object/address/ipv4Group')")
                    page.wait_for_selector("tbody[role='rowgroup']")

                    found_numbers = []
                    for tr in page.locator("tbody[role='rowgroup'] tr.group").all():
                        key_val = tr.get_attribute("key")
                        if key_val and key_val.startswith(group_prefix):
                            num_match = re.search(rf"{group_prefix}(\d+)", key_val)
                            if num_match:
                                found_numbers.append(int(num_match.group(1)))

                    if found_numbers:
                        self.device['group_name'] = f"{group_prefix}{max(found_numbers)}"
                        logger(f"🎯 최신 그룹 매칭: {self.device['group_name']}")

                # [Step 3] 그룹 내 객체 할당
                logger(f"[로그] 그룹 편집창 진입 ({self.device['group_name']})")
                page.evaluate(
                    f"window.location.replace('{self.base_url}/object/address/ipv4Group/edit?key={self.device['group_name']}')"
                )
                page.wait_for_selector("div.buttonExpandSearch")
                page.click("div.buttonExpandSearch")
                time.sleep(1)

                search_frame = page.frame_locator("#searchIframe")
                search_input = search_frame.locator("input#searchText")
                search_input.click()
                search_input.fill(self.target_ip)
                search_input.press("Enter")
                time.sleep(1)

                # 추가 버튼 클릭
                try:
                    add_btn = search_frame.locator(f"//img[@name='{self.obj_name}' and contains(@class, 'addBtn')]")
                    add_btn.click(timeout=3000)
                    logger(f"[로그] '{self.obj_name}' 그룹에 추가 완료")
                except Exception:
                    # addBtn을 못 눌렀다고 무조건 '이미 그룹에 있다'고 넘기지 않는다.
                    # 검색 결과에 객체 자체가 없다면(=생성이 안 됐다면) 확실한 실패이므로 즉시 중단한다.
                    exists_in_search = search_frame.locator(f"//img[@name='{self.obj_name}']").count() > 0
                    if exists_in_search:
                        logger(f"[알림] '{self.obj_name}'은(는) 이미 그룹에 포함되어 있는 것으로 보입니다. (추가 버튼 없음, 계속 진행)")
                    else:
                        raise Exception(
                            f"'{self.obj_name}' 객체가 그룹 추가 검색 결과에 나타나지 않습니다. "
                            f"객체 생성이 정상적으로 되지 않았을 가능성이 높습니다. 장비에서 직접 확인해주세요."
                        )

                time.sleep(1)
                if page.locator("//div[contains(., '등록 가능한 최대 개수를 초과합니다')]").count() > 0:
                    raise Exception(f"{self.device['group_name']}의 등록 용량이 초과되었습니다.")

                page.click("div.btnNormal.save")

                # [Step 4] 그룹 반영 및 최종 완료
                page.evaluate(f"window.location.replace('{self.base_url}/object/address/ipv4Group')")
                self._click_apply_and_confirm(page, logger)

                messagebox.showinfo(
                    "성공",
                    f"✨ [{self.device['name']}] 차단 완료!\n• 객체: {self.obj_name}\n• 매핑 그룹: {self.device['group_name']}",
                )

            except Exception as e:
                logger(f"❌ [중단 예외 발생]: {str(e)}")
                messagebox.showerror("오류 발생", str(e))
            finally:
                logger("[로그] 장비 세션 종료")
                try:
                    if context and page and not page.is_closed():
                        page.evaluate(f"window.location.replace('{self.base_url}/login/logout')")
                        time.sleep(0.8)
                except:
                    pass
                if context:
                    context.close()
                if browser:
                    browser.close()


class FortiGateSSHBot(BaseFirewallBot):
    def run(self, logger):
        logger(f"▶ [{self.device['name']}] 포티게이트 연결 시작 (구현 대기)")
        messagebox.showinfo("알림", "포티게이트 접속 로직 연동 대기 중입니다.")

# =============================================================================
# 3. GUI 화면 구성 (다크모드 & 예외 IP 기능 탑재)
# =============================================================================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ModernAppGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("통합 방화벽 관제 자동화 시스템")
        self.geometry("600x700")
        self.devices_data = load_devices_data()
        self.is_fullscreen = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._create_top_bar()
        self._create_input_section()
        self._create_log_section()
        self._on_device_changed(list(self.devices_data.keys())[0])

    def _create_top_bar(self):
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=15)
        top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top_frame, text="🛡️ Firewall Automation Tool", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, sticky="w")

        # 예외 IP 관리 & 전체화면 토글
        btn_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        btn_frame.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(btn_frame, text="⚙️ 예외 IP 설정", width=100, fg_color="#455A64", hover_color="#37474F", command=self._open_whitelist_manager).pack(side="left", padx=10)
        self.fullscreen_switch = ctk.CTkSwitch(btn_frame, text="전체화면", command=self.toggle_fullscreen)
        self.fullscreen_switch.pack(side="left")

    def _open_whitelist_manager(self):
        """예외 IP를 관리하는 별도의 팝업창을 엽니다."""
        wl_window = ctk.CTkToplevel(self)
        wl_window.title("예외 IP (Whitelist) 관리")
        wl_window.geometry("400x400")
        wl_window.attributes("-topmost", True)

        ctk.CTkLabel(wl_window, text="차단하면 안 되는 IP/대역대를 한 줄씩 입력하세요.\n(예: 8.8.8.8 또는 10.10.10.0/24)", font=ctk.CTkFont(weight="bold")).pack(pady=10)

        txt_wl = ctk.CTkTextbox(wl_window, width=350, height=280)
        txt_wl.pack(pady=5)

        # 기존 목록 불러오기
        current_wl = load_whitelist()
        txt_wl.insert("1.0", "\n".join(current_wl))

        def save_and_close():
            raw_text = txt_wl.get("1.0", "end").strip().split("\n")
            clean_list = [ip.strip() for ip in raw_text if ip.strip()]
            save_whitelist(clean_list)
            messagebox.showinfo("저장 완료", "예외 IP 목록이 성공적으로 저장되었습니다.", parent=wl_window)
            wl_window.destroy()

        ctk.CTkButton(wl_window, text="목록 저장", command=save_and_close, fg_color="#1976D2").pack(pady=10)

    def _create_input_section(self):
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        input_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_frame, text="대상 장비", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=15, pady=15, sticky="w")
        self.combo_device = ctk.CTkOptionMenu(input_frame, values=list(self.devices_data.keys()), command=self._on_device_changed, dynamic_resizing=False, width=250)
        self.combo_device.grid(row=0, column=1, padx=15, pady=15, sticky="w")

        ctk.CTkLabel(input_frame, text="차단 대상 IP", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=15, pady=10, sticky="w")
        self.ent_ip = ctk.CTkEntry(input_frame, placeholder_text="예: 1.1.1.1 또는 1.1.1.0/24", width=250)
        self.ent_ip.grid(row=1, column=1, padx=15, pady=10, sticky="w")

        self.lbl_country = ctk.CTkLabel(input_frame, text="국가 코드")
        self.ent_country = ctk.CTkEntry(input_frame, placeholder_text="예: KR, US", width=250)

        self.lbl_case = ctk.CTkLabel(input_frame, text="케이스 ID")
        self.ent_case = ctk.CTkEntry(input_frame, placeholder_text="예: 12345678", width=250)

        self.btn_run = ctk.CTkButton(input_frame, text="▶ 자동화 실행", font=ctk.CTkFont(weight="bold", size=14), fg_color="#C62828", hover_color="#B71C1C", command=self._start_automation)
        self.btn_run.grid(row=4, column=0, columnspan=2, padx=15, pady=20, sticky="ew")

    def _create_log_section(self):
        log_frame = ctk.CTkFrame(self)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(5, 20))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(log_frame, text="📝 실시간 작업 로그 모니터", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.txt_log = ctk.CTkTextbox(log_frame, text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=13))
        self.txt_log.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.log("시스템 준비 완료. (Whitelist 및 JSON 연결 됨)")

    def toggle_fullscreen(self):
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)
        if not self.is_fullscreen:
            self.geometry("600x700")

    def log(self, message):
        self.txt_log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.txt_log.see("end")
        self.update()

    def _on_device_changed(self, choice):
        dev_info = self.devices_data[choice]
        fmt_type = dev_info.get("format_type", 1)

        if fmt_type == 1:
            self.lbl_country.grid(row=2, column=0, padx=15, pady=10, sticky="w")
            self.ent_country.grid(row=2, column=1, padx=15, pady=10, sticky="w")
            self.lbl_case.grid(row=3, column=0, padx=15, pady=10, sticky="w")
            self.ent_case.grid(row=3, column=1, padx=15, pady=10, sticky="w")
        else:
            self.lbl_country.grid_forget()
            self.ent_country.grid_forget()
            self.ent_country.delete(0, "end")
            self.lbl_case.grid_forget()
            self.ent_case.grid_forget()
            self.ent_case.delete(0, "end")

    def _start_automation(self):
        choice = self.combo_device.get()
        dev_info = self.devices_data[choice]
        target_ip = self.ent_ip.get().strip()
        country_code = self.ent_country.get().strip()
        case_id = self.ent_case.get().strip()

        # 1. IP 유효성 검증
        if not target_ip:
            messagebox.showwarning("누락", "IP 주소를 입력하세요.")
            return
        try:
            if "/" not in target_ip:
                ipaddress.IPv4Address(target_ip)
            else:
                ipaddress.IPv4Network(target_ip, strict=False)
        except:
            messagebox.showerror("오류", "유효한 IP 또는 서브넷 형식이 아닙니다.")
            return

        # 2. 예외 IP (Whitelist) 통과 여부 검사
        whitelist = load_whitelist()
        if is_ip_whitelisted(target_ip, whitelist):
            messagebox.showwarning("차단 거부", f"입력하신 IP({target_ip})는 '예외 IP 목록'에 등록되어 있어 차단할 수 없습니다.")
            self.log(f"🚫 [차단 거부됨] 예외 목록에 등록된 IP 접근 시도: {target_ip}")
            return

        if dev_info.get("format_type", 1) == 1 and (not country_code or not case_id):
            messagebox.showwarning("누락", "국가 코드와 케이스 ID를 입력하세요.")
            return

        self.btn_run.configure(state="disabled")
        self.txt_log.delete("1.0", "end")

        dev_type = dev_info.get("type", "TRUSGUARD")
        if dev_type == "FORTIGATE":
            bot = FortiGateSSHBot(dev_info, target_ip, country_code, case_id)
        else:
            bot = TrusGuardWebBot(dev_info, target_ip, country_code, case_id)

        try:
            bot.run(self.log)
        except Exception as e:
            # 브라우저 기동 실패 등 bot.run() 내부에서 처리되지 못한 예외를 여기서 반드시 표시
            self.log(f"❌ [치명적 오류] {e}")
            messagebox.showerror("오류 발생", str(e))

        self.btn_run.configure(state="normal")

if __name__ == "__main__":
    app = ModernAppGUI()
    app.mainloop()
