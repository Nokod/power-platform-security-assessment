import os

import pandas as pd
import plotly.graph_objects as go
from jinja2 import Template

from power_platform_security_assessment.base_classes import User, CloudFlow, Application, ModelDrivenApp, DesktopFlow, \
    ConnectorWithConnections, Environment
from power_platform_security_assessment.consts import ComponentType
from power_platform_security_assessment.security_features.common import is_app_disabled, is_flow_disabled, \
    is_model_driven_app_disabled, is_desktop_flow_disabled
from power_platform_security_assessment.utils import get_environment_developers_count, round_time_to_seconds


class ReportBuilder:
    BACKGROUND_COLOR = '#f9fafb'
    TITLE_COLOR = '#b0b7c5'
    MAIN_BLUE = '#2253f5'
    MAIN_GRAY = '#62708b'
    MAIN_GREEN = '#00b384'
    MAIN_RED = '#f04438'
    VULN_COLOR = '#9c9c9c'
    GOVERNANCE_COLOR = '#ffa338'
    MALICIOUS_COLOR = '#ff3838'

    def __init__(self, applications: list[Application], cloud_flows: list[CloudFlow], desktop_flows: list[DesktopFlow],
                 model_driven_apps: list[ModelDrivenApp], users: list[User],
                 connectors: list[ConnectorWithConnections], environments_results: list, failed_environments: list,
                 environments: list[Environment], total_envs: int):
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

    def build_report(self, extra_textual_reports: list[str] = None):
        env_summary = [self._build_env_summary()]
        environment_reports = [self._build_bar_chart_summary(), self._build_components_in_env(),
                               self._build_connectors_in_env()]
        user_reports = [self._build_users_pie_charts()]
        top_3_reports = [self._build_biggest_environments(), self._build_used_connections()]
        email_body = self._build_email_body()
        failed_environments = [env[ComponentType.ENVIRONMENT].properties.displayName for env in
                               self._failed_environments]
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(__location__, 'report.html')) as f:
            template = Template(f.read())

        rendered_template = template.render(found_environments=env_summary, environment_reports=environment_reports,
                                            user_reports=user_reports, top_3_reports=top_3_reports,
                                            security_issues=extra_textual_reports, email_body=email_body,
                                            failed_environments=failed_environments)
        with open('output.html', 'w') as f:
            f.write(rendered_template)
            print(f'Report generated successfully. Output saved to {os.path.abspath("output.html")}')

    def _build_email_body(self):
        data = self.get_components_per_env()
        output = []
        for i, env in enumerate(data):
            output.append(
                f'Environment \'Env{i + 1}\' has {env["Applications"]} applications, {env["Cloud Flows"]} cloud '
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
            layout={'plot_bgcolor': self.BACKGROUND_COLOR, 'width': 1400, 'margin': dict(l=0, r=0, t=50, b=0)})
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

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
        status = 'Failed' if failed else 'Success'
        env_data = {'Name': env_name, 'Type': env_type, 'Created By': created_by, 'Create Time': created_time,
                    'Last Activity': last_activity, 'Scan Status': status}
        return env_data

    def _build_components_in_env(self):
        data = self.get_components_per_env()
        df = pd.DataFrame(data)
        fig = go.Figure(data=[go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Name'], df['Applications'], df['Cloud Flows'], df['Desktop Flows'],
                               df['Model Driven Apps'], df['Total']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left'))],
            layout={'title': 'Components per Environment', 'plot_bgcolor': self.BACKGROUND_COLOR,
                    'margin': dict(l=0, r=0, t=50, b=0)})
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

    def get_components_per_env(self):
        data = [{'Name': env[ComponentType.ENVIRONMENT].properties.displayName,
                 'Applications': env[ComponentType.APPLICATIONS].count,
                 'Cloud Flows': env[ComponentType.CLOUD_FLOWS].count,
                 'Desktop Flows': env[ComponentType.DESKTOP_FLOWS].count,
                 'Model Driven Apps': env[ComponentType.MODEL_DRIVEN_APPS].count,
                 'Total': env[ComponentType.APPLICATIONS].count + env[ComponentType.CLOUD_FLOWS].count + env[
                     ComponentType.DESKTOP_FLOWS].count + env[ComponentType.MODEL_DRIVEN_APPS].count + env[
                              ComponentType.USERS].count
                 } for env in self._environments_results]
        rows = sorted(data, key=lambda x: x['Total'], reverse=True)
        total_row = {'Name': '<b>Total</b>',
                     'Applications': f'<b>{sum([row["Applications"] for row in rows])}</b>',
                     'Cloud Flows': f'<b>{sum([row["Cloud Flows"] for row in rows])}</b>',
                     'Desktop Flows': f'<b>{sum([row["Desktop Flows"] for row in rows])}</b>',
                     'Model Driven Apps': f'<b>{sum([row["Model Driven Apps"] for row in rows])}</b>',
                     'Total': f'<b>{sum([row["Total"] for row in rows])}</b>'}

        return rows + [total_row]

    def _build_biggest_environments(self):
        envs = self._get_biggest_environments()
        df = pd.DataFrame(envs[:3])
        fig = go.Figure(data=[go.Table(
            header=dict(values=list(df.columns),
                        fill_color=self.TITLE_COLOR,
                        align='left'),
            cells=dict(values=[df['Environment Name'], df['Type'], df['Total Components'], df['Developers']],
                       fill_color=self.BACKGROUND_COLOR,
                       align='left'))],
            layout={'title': 'Top 3 Biggest Environments', 'height': 300})
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

    def _get_biggest_environments(self):
        envs = []
        for env in self._environments_results:
            env_name = env[ComponentType.ENVIRONMENT].properties.displayName
            apps_count = env[ComponentType.APPLICATIONS].count
            flows_count = env[ComponentType.CLOUD_FLOWS].count
            connections_count = env[ComponentType.CONNECTIONS].count
            users_count = env[ComponentType.USERS].count
            total_components = apps_count + flows_count + connections_count + users_count
            envs.append({'Environment Name': env_name, 'Type': env[ComponentType.ENVIRONMENT].properties.environmentSku,
                         'Total Components': total_components, 'Developers': get_environment_developers_count(env)})
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
            layout={'title': 'Top 3 Most Used Connectors', 'height': 300})
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

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
            layout={'title': 'Connectors per environment',
                    'plot_bgcolor': self.BACKGROUND_COLOR, 'height': 450, 'margin': dict(l=0, r=0, t=50, b=0)})
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

    def _get_connectors_in_env_data(self):
        data = [{'Environment Name': env[ComponentType.ENVIRONMENT].properties.displayName, 'Number of Connectors': len(
            env[ComponentType.CONNECTIONS].value)} for env in self._environments_results]
        data = sorted(data, key=lambda x: x['Number of Connectors'], reverse=True)
        return data

    def _build_users_pie_charts(self):
        df1, df2, df3 = self._get_pie_charts()

        fig1 = go.Figure(
            data=[go.Pie(labels=df1['Type'], values=df1['Count'], name='Internal vs Guest Users',
                         marker=dict(colors=[self.MAIN_BLUE, self.MAIN_GRAY]))],
            layout={'title': 'Internal vs Guest Users', 'height': 300, 'width': 350})
        fig2 = go.Figure(
            data=[go.Pie(labels=df2['Type'], values=df2['Count'], name='Enabled vs Disabled Users',
                         marker=dict(colors=[self.MAIN_GREEN, self.MAIN_RED]))],
            layout={'title': 'Enabled vs Disabled Users', 'height': 300, 'width': 350})
        fig3 = go.Figure(
            data=[go.Pie(labels=df3['Type'], values=df3['Count'], name='Azure State Users',
                         marker=dict(colors=[self.VULN_COLOR, self.GOVERNANCE_COLOR, self.MALICIOUS_COLOR]))],
            layout={'title': 'Azure State Users', 'height': 300, 'width': 350})
        return (fig1.to_html(full_html=False, include_plotlyjs='cdn')
                + fig2.to_html(full_html=False, include_plotlyjs='cdn')
                + fig3.to_html(full_html=False, include_plotlyjs='cdn'))

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
        df3 = pd.DataFrame({'Type': ['Active (0)', 'AD soft delete (1)', 'AD hard delete (2)'],
                            'Count': [azure_state_0, azure_state_1, azure_state_2]})
        return df1, df2, df3

    def _build_bar_chart_summary(self):
        main_green = '#00b384'
        main_red = '#f04438'

        df = self._get_bar_chart_data()
        fig = go.Figure(
            data=[
                go.Bar(name='Enabled', x=df.columns, y=df.iloc[0], marker=dict(color=main_green)),
                go.Bar(name='Disabled', x=df.columns, y=df.iloc[1], marker=dict(color=main_red))
            ],
            layout={
                'barmode': 'stack',
                'title': 'Total component per type',
                'plot_bgcolor': self.BACKGROUND_COLOR,
            }
        )
        return fig.to_html(full_html=False, include_plotlyjs='cdn')

    def _get_bar_chart_data(self):
        enabled_apps = len([app for app in self._applications if not is_app_disabled(app)])
        enabled_cloud_flows = len([flow for flow in self._cloud_flows if not is_flow_disabled(flow)])
        enabled_desktop_flows = len([flow for flow in self._desktop_flows if not is_desktop_flow_disabled(flow)])
        enabled_model_driven_apps = len(
            [app for app in self._model_driven_apps if not is_model_driven_app_disabled(app)])
        df = pd.DataFrame({
            'Applications': [enabled_apps, len(self._applications) - enabled_apps],
            'Cloud Flows': [enabled_cloud_flows, len(self._cloud_flows) - enabled_cloud_flows],
            'Desktop Flows': [enabled_desktop_flows, len(self._desktop_flows) - enabled_desktop_flows],
            'Model Driven Apps': [enabled_model_driven_apps, len(self._model_driven_apps) - enabled_model_driven_apps],
        })
        return df
