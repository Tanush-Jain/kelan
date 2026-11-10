import sys
from unittest import mock

from kelan.cli.main import cmd_menu, main


@mock.patch("kelan.cli.main.cmd_menu")
def test_entrypoint_no_args_triggers_menu(mock_menu):
    with mock.patch("sys.argv", ["kelan"]):
        main()
        mock_menu.assert_called_once()


@mock.patch("kelan.cli.main._delegate")
@mock.patch("kelan.cli.main.Prompt.ask")
def test_menu_git(mock_prompt_ask, mock_delegate):

    mock_prompt_ask.side_effect = ["git", "https://github.com/example/repo.git", "exit"]
    mock_delegate.return_value = 0
    
    cmd_menu()
    
    mock_delegate.assert_called_once()
    assert sys.argv == ["kelan", "https://github.com/example/repo.git", "--show"]


@mock.patch("kelan.cli.main._delegate")
@mock.patch("kelan.cli.main.Prompt.ask")
def test_menu_sast(mock_prompt_ask, mock_delegate):

    mock_prompt_ask.side_effect = ["sast", "./my-target", "exit"]
    mock_delegate.return_value = 0
    
    cmd_menu()
    
    mock_delegate.assert_called_once()
    assert sys.argv == ["kelan", "./my-target", "--show"]


@mock.patch("kelan.cli.main._start_dashboard_server")
@mock.patch("kelan.cli.main._delegate", return_value=0)
def test_dashboard_not_launched_by_default(mock_delegate, mock_start_dash):
    main(["run", "target"])
    mock_start_dash.assert_not_called()


@mock.patch("kelan.cli.main._stop_dashboard_server")
@mock.patch("kelan.cli.main._start_dashboard_server")
@mock.patch("kelan.cli.main._delegate", return_value=0)
def test_dashboard_launched_and_stopped_with_flag(mock_delegate, mock_start_dash, mock_stop_dash):
    mock_proc = mock.MagicMock()
    mock_start_dash.return_value = mock_proc
    main(["run", "target", "--dashboard"])
    mock_start_dash.assert_called_once()
    mock_stop_dash.assert_called_once_with(mock_proc)
