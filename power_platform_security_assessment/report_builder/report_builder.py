import pandas as pd
import plotly.graph_objects as go
from jinja2 import Template
from plotly.subplots import make_subplots

from power_platform_security_assessment.base_classes import User, CloudFlow, Application, ModelDrivenApp, DesktopFlow, \
    ConnectorWithConnections
from power_platform_security_assessment.consts import ComponentType
from power_platform_security_assessment.security_features.common import is_app_disabled, is_flow_disabled, \
    is_model_driven_app_disabled, is_desktop_flow_disabled


class ReportBuilder:
    BACKGROUND_COLOR = '#f9fafb'
    TITLE_COLOR = '#b0b7c5'

    def __init__(self, applications: list[Application], cloud_flows: list[CloudFlow], desktop_flows: list[DesktopFlow],
                 model_driven_apps: list[ModelDrivenApp], users: list[User],
                 connectors: list[ConnectorWithConnections], environments_results: list):
        self.fig = None
        self.applications = applications
        self.cloud_flows = cloud_flows
        self.desktop_flows = desktop_flows
        self.model_driven_apps = model_driven_apps
        self.users = users
        self.connectors = connectors
        self.environments_results = environments_results

    def build_report(self, extra_textual_reports: list[str] = None):
        users_pie_charts = self._build_users_pie_charts()

        fig1 = self._build_bar_chart_summary()
        fig2 = self._build_top_3_connectors()
        fig3 = self._build_tables()

        htmls = [fig1.to_html(full_html=False, include_plotlyjs='cdn') + fig2.to_html(full_html=False,
                                                                                      include_plotlyjs='cdn'),
                 fig3.to_html(full_html=False, include_plotlyjs='cdn'),
                 users_pie_charts]

        template = Template(
            open(
                '/Users/riftin/Documents/Public/power-platform-security-assessment/power_platform_security_assessment/report_builder/report.html').read())
        rendered_template = template.render(reports=htmls, extra_textual_reports=extra_textual_reports)
        with open('output.html', 'w') as f:
            f.write(rendered_template)

    def _build_tables(self):
        fig = make_subplots(rows=1, cols=2,
                            specs=[[{'type': 'table'}, {'type': 'table'}]],
                            subplot_titles=('Biggest Environments', 'Used Connections'))
        self._build_biggest_environments(fig)
        self._build_used_connections(fig)

        fig.update_layout(width=1900, height=300)
        return fig

    def _build_biggest_environments(self, fig):
        envs = []
        for env in self.environments_results:
            env_name = env[ComponentType.ENVIRONMENT].properties.displayName
            apps_count = env[ComponentType.APPLICATIONS].count
            flows_count = env[ComponentType.CLOUD_FLOWS].count
            connections_count = env[ComponentType.CONNECTIONS].count
            users_count = env[ComponentType.USERS].count
            total_components = apps_count + flows_count + connections_count + users_count
            envs.append({'Environment Name': env_name, 'Type': env[ComponentType.ENVIRONMENT].properties.environmentSku,
                         'Total Components': total_components, 'Developers': ''})

        sorted(envs, key=lambda x: x['Total Components'], reverse=True)

        df = pd.DataFrame(envs[:3])
        fig.add_trace(go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Environment Name'], df['Type'], df['Total Components'], df['Developers']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left')), row=1, col=2,
        )

    def _build_used_connections(self, fig):
        connectors = []
        for connector_with_connections in self.connectors[:3]:
            connector = connector_with_connections.connector
            connections_count = len(connector_with_connections.connections)
            connectors.append({'Name': connector.name, 'Publisher': connector.properties.publisher,
                               'Connections Count': connections_count})

        df = pd.DataFrame(connectors)
        fig.add_trace(go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Name'], df['Publisher'], df['Connections Count']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left')), row=1, col=1)

    def _build_top_3_connectors(self):
        main_blue = '#2253f5'
        df = pd.DataFrame({
            'Environment Name': [env[ComponentType.ENVIRONMENT].properties.displayName for env in
                                 self.environments_results],
            'Number of Connectors': [len(env[ComponentType.CONNECTIONS].value) for env in self.environments_results]
        })

        fig = go.Figure(
            data=[go.Bar(x=df['Environment Name'], y=df['Number of Connectors'], marker=dict(color=main_blue))],
            layout={'title': 'Top 3 Connectors Usage', 'width': 800, 'height': 450,
                    'plot_bgcolor': self.BACKGROUND_COLOR})
        return fig

    def _build_users_pie_charts(self):
        main_blue = '#2253f5'
        main_gray = '#62708b'
        main_green = '#00b384'
        main_red = '#f04438'
        vuln_color = '#9c9c9c'
        governance_color = '#ffa338'
        malicious_color = '#ff3838'

        guest_users = len([user for user in self.users if user.domainname.find('#EXT#') != -1])
        enabled_users = len([user for user in self.users if not user.isdisabled])
        disabled_users = len([user for user in self.users if user.isdisabled])
        azure_state_0 = len([user for user in self.users if not user.azurestate])
        azure_state_1 = len([user for user in self.users if user.azurestate == 1])
        azure_state_2 = len([user for user in self.users if user.azurestate == 2])

        df1 = pd.DataFrame(
            {'Type': ['Internal Users', 'Guest Users'], 'Count': [len(self.users) - guest_users, guest_users]})
        df2 = pd.DataFrame({'Type': ['Enabled Users', 'Disabled Users'], 'Count': [enabled_users, disabled_users]})
        df3 = pd.DataFrame({'Type': ['Active (0)', 'AD soft delete (1)', 'AD hard delete (2)'],
                            'Count': [azure_state_0, azure_state_1, azure_state_2]})

        fig = make_subplots(rows=1, cols=3, specs=[[{'type': 'domain'}, {'type': 'domain'}, {'type': 'domain'}]],
                            subplot_titles=(
                                'Internal vs Guest Users', 'Enabled vs Disabled Users', 'Azure State Users'))

        fig.add_trace(go.Pie(labels=df1['Type'], values=df1['Count'], name='Internal vs Guest Users',
                             marker=dict(colors=[main_blue, main_gray])), row=1, col=1)
        fig.add_trace(go.Pie(labels=df2['Type'], values=df2['Count'], name='Enabled vs Disabled Users',
                             marker=dict(colors=[main_green, main_red])), row=1, col=2)
        fig.add_trace(go.Pie(labels=df3['Type'], values=df3['Count'], name='Azure State Users',
                             marker=dict(colors=[vuln_color, governance_color, malicious_color])), row=1, col=3)

        fig.update_layout(width=1200, height=400)
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

    def _build_bar_chart_summary(self):
        main_green = '#00b384'
        main_red = '#f04438'

        enabled_apps = len([app for app in self.applications if not is_app_disabled(app)])
        enabled_cloud_flows = len([flow for flow in self.cloud_flows if not is_flow_disabled(flow)])
        enabled_desktop_flows = len([flow for flow in self.desktop_flows if not is_desktop_flow_disabled(flow)])
        enabled_model_driven_apps = len(
            [app for app in self.model_driven_apps if not is_model_driven_app_disabled(app)])
        enabled_users = len([user for user in self.users if not user.isdisabled])

        df = pd.DataFrame({
            'Applications': [enabled_apps, len(self.applications) - enabled_apps],
            'Cloud Flows': [enabled_cloud_flows, len(self.cloud_flows) - enabled_cloud_flows],
            'Desktop Flows': [enabled_desktop_flows, len(self.desktop_flows) - enabled_desktop_flows],
            'Model Driven Apps': [enabled_model_driven_apps, len(self.model_driven_apps) - enabled_model_driven_apps],
            'Users': [enabled_users, len(self.users) - enabled_users],
        })
        fig = go.Figure(
            data=[
                go.Bar(name='Enabled', x=df.columns, y=df.iloc[0], marker=dict(color=main_green)),
                go.Bar(name='Disabled', x=df.columns, y=df.iloc[1], marker=dict(color=main_red))
            ],
            layout={
                'barmode': 'stack',
                'title': 'Enabled vs Disabled Components',
                'width': 800,
                'height': 450,
                'plot_bgcolor': self.BACKGROUND_COLOR,
            }
        )
        return fig
