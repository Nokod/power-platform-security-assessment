import os

import pandas as pd
import plotly.graph_objects as go
from jinja2 import Template

from power_platform_security_assessment.base_classes import User, CloudFlow, Application, ModelDrivenApp, DesktopFlow, \
    ConnectorWithConnections, Environment, ResourceData
from power_platform_security_assessment.consts import ComponentType
from power_platform_security_assessment.security_features.common import is_app_disabled, is_flow_disabled, \
    is_model_driven_app_disabled, is_desktop_flow_disabled
from power_platform_security_assessment.utils import get_environment_developers_count, round_time_to_seconds


class ReportBuilder:
    BACKGROUND_COLOR = '#f9fafb'
    TITLE_COLOR = '#b0b7c5'
    MAIN_BLUE = '#688bf8'
    MAIN_GRAY = '#62708b'
    MAIN_GREEN = '#50caa9'
    MAIN_RED = '#ff4b4b'
    MAIN_ORANGE = '#f9a14d'
    VULN_COLOR = '#9c9c9c'

    def __init__(self, applications: list[Application], cloud_flows: list[CloudFlow], desktop_flows: list[DesktopFlow],
                 model_driven_apps: list[ModelDrivenApp], users: list[User],
                 connectors: list[ConnectorWithConnections], environments_results: list, failed_environments: list,
                 environments: list[Environment], total_envs: int, all_users_fetched: bool):
        self._applications = applications
        self._cloud_flows = cloud_flows
        self._desktop_flows = desktop_flows
        self._model_driven_apps = model_driven_apps
        self._users = users
        self._connectors = connectors
        self._scanned_environments = environments
        self._environments_results = environments_results
        self._failed_environments = failed_environments
        self._total_envs_count = total_envs
        self._all_users_fetched = all_users_fetched

    def build_report(self, app_developers_report, connectors_report, bypass_consent_report):
        env_summary = [self._build_env_summary()]
        environment_reports = [
            self._build_bar_chart_summary(),
            self._build_components_in_env(),
            self._build_connectors_in_env(),
        ]
        user_reports = [self._build_users_pie_charts()]
        top_3_reports = [self._build_biggest_environments(), self._build_used_connections()]
        email_body = self._build_email_body()
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__)))

        with open(os.path.join(__location__, 'report.html')) as f:
            template = Template(f.read())

        rendered_template = template.render(
            found_environments=env_summary,
            environment_reports=environment_reports,
            total_users=f'{len(self._users)}' + ("+" if not self._all_users_fetched else ""),
            user_reports=user_reports,
            app_developers_report=app_developers_report,
            connectors_report=connectors_report,
            bypass_consent_report=bypass_consent_report,
            top_3_reports=top_3_reports,
            email_body=email_body,
            report_date=pd.Timestamp.now().strftime('%B %d, %Y'),
            total_envs_count=self._total_envs_count,
        )
        with open('power_platform_scan_report.html', 'w') as f:
            f.write(rendered_template)
            print(f'Report generated successfully. Output saved to {os.path.abspath("power_platform_scan_report.html")}')

    def _build_email_body(self):
        data = self.get_components_per_env()[:-1]
        output = [
            f'Hello Nokod Team,\\n'
            f'I would like to discuss the results of the scan I made.\\n'
            f'See below findings.\\n'
        ]
        for i, env in enumerate(data):
            output.append(
                f'Environment \'Env{i + 1}\' has {env["Canvas Apps"]} applications, {env["Cloud Flows"]} cloud '
                f'flows, {env["Desktop Flows"]} desktop flows, and {env["Model Driven Apps"]} model driven apps. '
                f'This totals to {env["Total"]} components.')
        return "\\n".join(output)

    def _build_env_summary(self):
        envs = self.get_scanned_environments()
        df = pd.DataFrame(envs)
        fig = go.Figure(data=[go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Name'], df['Type'], df['Created By'], df['Create Time'], df['Last Activity'],
                               df['Scan Status']],
                       fill_color=self.BACKGROUND_COLOR,
                       line=dict(color='white'),
                       align='left'))],
            layout={
                'plot_bgcolor': self.BACKGROUND_COLOR,
                'width': 1400,
                'height': 150 + (len(envs) * 20),
                'margin': dict(l=0, r=0, t=50, b=50),
                'annotations': [
                    go.layout.Annotation(
                        x=0, y=-0.1, showarrow=False, xanchor='left', yanchor='bottom',
                        text=f'Total number of environments: {self._total_envs_count}. '
                    ),
                ],
            }
        )

        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    def get_scanned_environments(self):
        envs = []
        for env in self._scanned_environments:
            envs.append(self._create_env_data(
                env=env,
                failed=env.name in [env[ComponentType.ENVIRONMENT].name for env in self._failed_environments]
            ))

        return envs

    @staticmethod
    def _create_env_data(env: Environment, failed=False):
        env_name = env.properties.displayName
        created_by = env.properties.createdBy.get('displayName', 'N/A')
        created_time = round_time_to_seconds(env.properties.createdTime)
        last_activity = round_time_to_seconds(env.properties.lastActivity.lastActivity.lastActivityTime)
        env_type = env.properties.environmentSku
        status = 'Failed - insufficient permissions' if failed else 'Success'
        env_data = {'Name': env_name, 'Type': env_type, 'Created By': created_by, 'Create Time': created_time,
                    'Last Activity': last_activity, 'Scan Status': status}
        return env_data

    def _build_components_in_env(self):
        data = self.get_components_per_env()
        df = pd.DataFrame(data)
        fig = go.Figure(data=[go.Table(
            header=dict(
                values=[
                    'Name',
                    '<a href="https://learn.microsoft.com/en-us/power-apps/maker/canvas-apps/getting-started">Canvas Apps</a>',
                    '<a href="https://learn.microsoft.com/en-us/power-automate/overview-cloud">Cloud Flows</a>',
                    '<a href="https://learn.microsoft.com/en-us/power-automate/desktop-flows/introduction">Desktop Flows</a>',
                    '<a href="https://learn.microsoft.com/en-us/power-apps/maker/model-driven-apps/model-driven-app-overview">Model Driven Apps</a>',
                    'Total'
                ],
                fill_color=self.TITLE_COLOR,
                align='left'
            ),
            cells=dict(values=[df['Name'], df['Canvas Apps'], df['Cloud Flows'], df['Desktop Flows'],
                               df['Model Driven Apps'], df['Total']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left'))],
            layout={'title': {'text': 'Components per Environment', 'x': 0.5}, 'plot_bgcolor': self.BACKGROUND_COLOR,
                    'margin': dict(l=10, r=10, t=100, b=0)})
        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    @staticmethod
    def _get_component_count(resource_data: ResourceData) -> tuple:
        count = resource_data.count
        display = f'{count}' + ("+" if not resource_data.all_resources_fetched else "")
        return count, display

    def get_components_per_env(self):
        data = []
        for env in self._environments_results:
            canvas_count, canvas_display = self._get_component_count(env[ComponentType.APPLICATIONS])
            cloud_count, cloud_display = self._get_component_count(env[ComponentType.CLOUD_FLOWS])
            desktop_count, desktop_display = self._get_component_count(env[ComponentType.DESKTOP_FLOWS])
            model_count, model_display = self._get_component_count(env[ComponentType.MODEL_DRIVEN_APPS])
            total_count = canvas_count + cloud_count + desktop_count + model_count
            total_display = f'{total_count}' + ("+" if not all([env[ComponentType.APPLICATIONS].all_resources_fetched,
                                                                env[ComponentType.CLOUD_FLOWS].all_resources_fetched,
                                                                env[ComponentType.DESKTOP_FLOWS].all_resources_fetched,
                                                                env[ComponentType.MODEL_DRIVEN_APPS].all_resources_fetched]) else "")
            data.append({
                'Name': env[ComponentType.ENVIRONMENT].properties.displayName,
                'Canvas Apps': canvas_display,
                'Cloud Flows': cloud_display,
                'Desktop Flows': desktop_display,
                'Model Driven Apps': model_display,
                'Total': total_display
            })

        rows = sorted(data, key=lambda x: int(x['Total'].rstrip('+')), reverse=True)
        total_row = {
            'Name': '<b>Total</b>',
            'Canvas Apps': f'<b>{sum(int(row["Canvas Apps"].rstrip("+")) for row in rows)}</b>',
            'Cloud Flows': f'<b>{sum(int(row["Cloud Flows"].rstrip("+")) for row in rows)}</b>',
            'Desktop Flows': f'<b>{sum(int(row["Desktop Flows"].rstrip("+")) for row in rows)}</b>',
            'Model Driven Apps': f'<b>{sum(int(row["Model Driven Apps"].rstrip("+")) for row in rows)}</b>',
            'Total': f'<b>{sum(int(row["Total"].rstrip("+")) for row in rows)}</b>'
        }

        return rows + [total_row]

    def _build_biggest_environments(self):
        envs = self._get_biggest_environments()
        df = pd.DataFrame(envs[:3])
        fig = go.Figure(data=[go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Environment Name'], df['Type'], df['Total Components'], df['Developers *']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left'))],
            layout={'title': {'text': 'Top 3 Biggest Environments', 'x': 0.5}, 'height': 300, 'annotations': [
                go.layout.Annotation(x=0, y=-0.2, showarrow=False, xanchor='left', yanchor='bottom',
                                     text='* Developers are users who own at least one application in the '
                                          'environment')]})
        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    def _get_biggest_environments(self):
        envs = []
        for env in self._environments_results:
            env_name = env[ComponentType.ENVIRONMENT].properties.displayName
            apps_count = env[ComponentType.APPLICATIONS].count
            flows_count = env[ComponentType.CLOUD_FLOWS].count
            model_driven_apps_count = env[ComponentType.MODEL_DRIVEN_APPS].count
            desktop_flows_count = env[ComponentType.DESKTOP_FLOWS].count
            total_components = apps_count + flows_count + model_driven_apps_count + desktop_flows_count
            envs.append({'Environment Name': env_name, 'Type': env[ComponentType.ENVIRONMENT].properties.environmentSku,
                         'Total Components': total_components, 'Developers *': get_environment_developers_count(env)})
        envs = sorted(envs, key=lambda x: x['Total Components'], reverse=True)
        return envs

    def _build_used_connections(self):
        connectors = self._get_used_connections()

        df = pd.DataFrame(connectors)
        fig = go.Figure(data=[go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Name'], df['Publisher'], df['Connections Count']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left'))],
            layout={'title': {'text': 'Top 3 Most Used Connectors', 'x': 0.5}, 'height': 300})

        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    def _get_used_connections(self):
        connectors = []
        for connector_with_connections in self._connectors[:3]:
            connector = connector_with_connections.connector
            connections_count = len(connector_with_connections.connections)
            connectors.append({'Name': connector.properties.displayName, 'Publisher': connector.properties.publisher,
                               'Connections Count': connections_count})
        sorted(connectors, key=lambda x: x['Connections Count'])
        return connectors

    def _build_connectors_in_env(self):
        data = self._get_connectors_in_env_data()
        df = pd.DataFrame(data)
        fig = go.Figure(
            data=[go.Table(
                header=dict(values=list(df.columns),
                            fill_color=self.TITLE_COLOR,
                            align='left'),
                cells=dict(values=[df['Environment Name'], df['Number of Connectors']],
                           fill_color=self.BACKGROUND_COLOR,
                           align='left'))],
            layout={'title': {'text': 'Connectors per Environment', 'x': 0.5},
                    'plot_bgcolor': self.BACKGROUND_COLOR, 'height': 150 + (len(data) * 20), 'margin': dict(l=10, r=10, t=100, b=0)})
        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    def _get_connectors_in_env_data(self):
        data = [{'Environment Name': env[ComponentType.ENVIRONMENT].properties.displayName, 'Number of Connectors': len(
            env[ComponentType.CONNECTIONS].value)} for env in self._environments_results]
        data = sorted(data, key=lambda x: x['Number of Connectors'], reverse=True)
        return data

    def _build_users_pie_charts(self):
        df1, df2, df3 = self._get_pie_charts()

        fig1 = go.Figure(
            data=[go.Pie(labels=df1['Type'], values=df1['Count'], name='Internal vs Guest Users',
                         marker=dict(colors=[self.MAIN_GREEN, self.MAIN_ORANGE]))],
            layout={'title': {'text': 'Internal vs Guest Users', 'x': 0.5}, 'height': 300, 'width': 350}
        )
        fig2 = go.Figure(
            data=[go.Pie(labels=df2['Type'], values=df2['Count'], name='Enabled vs Disabled Users',
                         marker=dict(colors=[self.MAIN_GREEN, self.MAIN_RED]))],
            layout={'title': {'text': 'Enabled vs Disabled Users', 'x': 0.5}, 'height': 300, 'width': 350}
        )
        fig3 = go.Figure(
            data=[go.Pie(labels=df3['Type'], values=df3['Count'], name='Users in Active Directory',
                         marker=dict(colors=[self.MAIN_GREEN, self.MAIN_ORANGE, self.MAIN_RED]))],
            layout={'title': {'text': 'Users in Active Directory', 'x': 0.5}, 'height': 300, 'width': 350}
        )

        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}

        return (fig1.to_html(full_html=False, include_plotlyjs='cdn', config=config)
                + fig2.to_html(full_html=False, include_plotlyjs='cdn', config=config)
                + fig3.to_html(full_html=False, include_plotlyjs='cdn', config=config))

    def _get_pie_charts(self):
        guest_users = len([user for user in self._users if user.domainname.find('#EXT#') != -1])
        enabled_users = len([user for user in self._users if not user.isdisabled])
        disabled_users = len([user for user in self._users if user.isdisabled])
        azure_state_0 = len([user for user in self._users if not user.azurestate])
        azure_state_1 = len([user for user in self._users if user.azurestate == 1])
        azure_state_2 = len([user for user in self._users if user.azurestate == 2])
        df1 = pd.DataFrame(
            {'Type': ['Internal Users', 'Guest Users'], 'Count': [len(self._users) - guest_users, guest_users]})
        df2 = pd.DataFrame({'Type': ['Enabled Users', 'Disabled Users'], 'Count': [enabled_users, disabled_users]})
        df3 = pd.DataFrame({'Type': ['Active', 'AD Soft Delete', 'AD Hard Delete'],
                            'Count': [azure_state_0, azure_state_1, azure_state_2]})
        return df1, df2, df3

    def _build_bar_chart_summary(self):
        main_green = '#50caa9'
        main_red = '#ff4b4b'

        df = self._get_bar_chart_data()
        fig = go.Figure(
            data=[
                go.Bar(name='Enabled', x=df.columns, y=df.iloc[0], marker=dict(color=main_green)),
                go.Bar(name='Disabled', x=df.columns, y=df.iloc[1], marker=dict(color=main_red))
            ],
            layout={
                'barmode': 'stack',
                'title': {'text': 'Total Components per Type', 'x': 0.5},
                'plot_bgcolor': self.BACKGROUND_COLOR,
            }
        )
        config = {'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}
        return fig.to_html(full_html=False, include_plotlyjs='cdn', config=config)

    def _get_bar_chart_data(self):
        enabled_apps = len([app for app in self._applications if not is_app_disabled(app)])
        enabled_cloud_flows = len([flow for flow in self._cloud_flows if not is_flow_disabled(flow)])
        enabled_desktop_flows = len([flow for flow in self._desktop_flows if not is_desktop_flow_disabled(flow)])
        enabled_model_driven_apps = len(
            [app for app in self._model_driven_apps if not is_model_driven_app_disabled(app)])
        df = pd.DataFrame({
            'Canvas Apps': [enabled_apps, len(self._applications) - enabled_apps],
            'Cloud Flows': [enabled_cloud_flows, len(self._cloud_flows) - enabled_cloud_flows],
            'Desktop Flows': [enabled_desktop_flows, len(self._desktop_flows) - enabled_desktop_flows],
            'Model Driven Apps': [enabled_model_driven_apps, len(self._model_driven_apps) - enabled_model_driven_apps],
        })
        return df
